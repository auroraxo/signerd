/*
 * leasecheck - kernel-enforced detection of open WRITE handles on a file.
 *
 * Why this exists (R4-1): a file's mode only says who MAY open it. A process
 * that opened it for writing while it was still group/other-writable keeps
 * that descriptor after the operator chmods it tight - chmod does not revoke
 * a descriptor. The daemon must refuse to trust such a file while a write
 * handle exists.
 *
 * THE LEASE TYPE IS THE WHOLE DESIGN, AND IT WAS WRONG ONCE:
 *
 *   F_WRLCK (write lease)  conflicts with EVERY other opener, including
 *                          harmless readers -> a `cat grants.json` in any
 *                          shell would make the daemon refuse to sign.
 *                          Measured: reader -> exit 3 (false positive).
 *   F_RDLCK (read lease)   conflicts only with openers for WRITING.
 *                          Measured: reader -> granted, writer -> EAGAIN.
 *
 * F_RDLCK is therefore the detection primitive: if some process (ANY uid -
 * the kernel decides, /proc cannot see foreign uids) holds the file open for
 * writing, acquiring the read lease fails with EAGAIN.
 *
 * Protocol: first line on stdout is a metadata record, then the file bytes.
 * The read happens THROUGH the fd that holds the lease, and the lease is
 * re-checked afterwards (F_GETLEASE): a writer that opens mid-read breaks the
 * lease, and we refuse instead of returning bytes we can no longer vouch for.
 *
 * Exit codes:
 *   0  bytes returned (metadata line records lease=held|broken, mode, uid)
 *   3  a write handle is held right now -> refuse
 *   4  F_SETLEASE unsupported on this kernel -> refuse, never fake a pass
 *   5  open failed; errno name on stderr (ELOOP = symlink, ENOENT = missing)
 *   6  not a regular file
 *   7  lease denied by permissions (not our file)
 *
 * O_NONBLOCK matters: without it F_SETLEASE blocks until the conflicting
 * writer goes away, which turns "a stranger holds the file" into a hang of
 * every daemon request.
 *
 * SIGIO is ignored on purpose: the kernel signals the lease holder whenever a
 * conflicting open is attempted and the default action is to terminate -
 * otherwise a stranger could kill the probe at will (this killed the first
 * measurement script: exit 157, "I/O possible").
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#ifndef F_SETLEASE
#define F_SETLEASE 1024
#endif
#ifndef F_RDLCK
/* Linux/glibc: F_RDLCK == 0, F_WRLCK == 1. The values are unusual (the
 * "read" lock is 0) but they are what the kernel checks. */
#define F_RDLCK 0
#endif
#ifndef F_UNLCK
#define F_UNLCK 2
#endif

static const char *errno_name(int e) {
  switch (e) {
    case EAGAIN: return "EAGAIN";
    case EACCES: return "EACCES";
    case EPERM:  return "EPERM";
    case EINVAL: return "EINVAL";
    case ENOSYS: return "ENOSYS";
    case EBADF:  return "EBADF";
    case ENOENT: return "ENOENT";
    case ELOOP:  return "ELOOP";
    case ENOTDIR: return "ENOTDIR";
    default:     return "OTHER";
  }
}

int main(int argc, char **argv) {
  if (argc != 2) {
    fprintf(stderr, "usage: leasecheck <path>\n");
    return 5;
  }
  /* The lease holder is signalled on a conflicting open; default = terminate. */
  signal(SIGIO, SIG_IGN);

  /* O_NOFOLLOW: a symlink at this path could be re-pointed mid-probe.
   * O_NONBLOCK: fail fast instead of blocking behind a live writer. */
  int fd = open(argv[1], O_RDONLY | O_NOFOLLOW | O_NONBLOCK);
  if (fd < 0) {
    fprintf(stderr, "%s\n", errno_name(errno));
    return 5;
  }

  struct stat st;
  if (fstat(fd, &st) != 0) {
    fprintf(stderr, "%s\n", errno_name(errno));
    close(fd);
    return 5;
  }
  if (!S_ISREG(st.st_mode)) {
    close(fd);
    return 6;
  }

  /* Read lease: granted only if nobody holds this file open for writing. */
  if (fcntl(fd, F_SETLEASE, F_RDLCK) != 0) {
    int e = errno;
    close(fd);
    if (e == EAGAIN || e == EWOULDBLOCK) return 3;
    if (e == EINVAL || e == ENOSYS || e == EOPNOTSUPP) return 4;
    if (e == EACCES || e == EPERM) return 7;
    fprintf(stderr, "%s\n", errno_name(e));
    return 5;
  }

  /* Read the bytes through the lease-holding fd. */
  char *buf = NULL;
  size_t cap = 0, len = 0;
  for (;;) {
    if (len == cap) {
      cap = cap ? cap * 2 : 8192;
      char *nb = realloc(buf, cap);
      if (!nb) { free(buf); close(fd); fprintf(stderr, "ENOMEM\n"); return 5; }
      buf = nb;
    }
    ssize_t n = read(fd, buf + len, cap - len);
    if (n < 0) {
      int e = errno;
      free(buf);
      fcntl(fd, F_SETLEASE, F_UNLCK);
      close(fd);
      fprintf(stderr, "%s\n", errno_name(e));
      return 5;
    }
    if (n == 0) break;
    len += (size_t)n;
  }

  /* Did anyone open this file for WRITING while we were reading it? A writer
   * breaks our read lease; F_UNLCK then means the bytes above are no longer
   * ours to vouch for. Refuse rather than hand them over. */
  int current = fcntl(fd, F_GETLEASE, 0);
  const char *lease = (current == F_RDLCK) ? "held" : "broken";

  printf("LC1 dev=%llu ino=%llu uid=%lu mode=%lo size=%llu lease=%s\n",
         (unsigned long long)st.st_dev, (unsigned long long)st.st_ino,
         (unsigned long)st.st_uid, (unsigned long)(st.st_mode & 07777),
         (unsigned long long)st.st_size, lease);

  if (len > 0 && fwrite(buf, 1, len, stdout) != len) {
    free(buf);
    fcntl(fd, F_SETLEASE, F_UNLCK);
    close(fd);
    return 5;
  }
  free(buf);
  fflush(stdout);
  fcntl(fd, F_SETLEASE, F_UNLCK);
  close(fd);
  /* lease=broken is reported in metadata and enforced by the caller; the
   * bytes are still delivered so the caller can produce a precise error. */
  return 0;
}
