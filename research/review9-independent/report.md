# Review #9: unabhängige Adversarial-Review der Message-Grant-Envelope

2026-11-01, eigenständiger Review (Subagent, kein Autor des Codes). Scope laut
Auftrag: `src/policy-message.js` (inkl. der Änderung in `84888d4`, Parent
`20140e9`) und die Einbettung in Daemon/Client/Consumer.

Unabhängigkeits-Protokoll: `research/review9-independent/findings-first.md`
wurde vor dem ersten eigenen Probe und vor dem Öffnen der Alt-Reports
(`review5/`, `review6*`, `review7-envelope/`, `review8-r7diff/`) committet
(Commit `a2b3cd3`). Der Abgleich mit den Alt-Reports steht unten in
„Abgleich mit den Alt-Reports" (Überlappungen sind dort explizit markiert).

## Baseline

| Messung | Wert |
|---|---|
| `npm test` bei Auftragsannahme (HEAD `5770b59`, Branch `feature/message-grant-envelope`) | **186/186 pass**, 0 fail, 32.9 s |
| Node/Python | v24.20.0 / Python 3.12.3 |
| Repo-Zustand | sauber, kein in-flight Work |

Die Baseline entsprach dem erwarteten Wert 186/186; keine Abweichung zu
melden.

Nach den Fixes (eigener Branch `independent/envelope-review`):
**201/201 pass** (186 + 15 neue Regressionstests), 0 fail, 33.6 s.
Crash-Harness: unsealed **pass** (1/1), sealed **pass** (laufend, siehe
Abschnitt „Verifikation").

## Methode

Probes laufen gegen den LEBENDEN Daemon über einen echten Unix-Socket
(echter Keystore, echtes Ledger, echter Ed25519-Signer) oder direkt gegen die
Policy-/Ledger-Klasse, wenn der Fall deterministisch eingefroren werden muss
(Grenzwerte). Jeder Probe notiert den ERWARTETEN Verdict vor dem Lauf in
`findings-first.md` bzw. im Probe-Kommentar; Erwartung ≠ Messung = Befund
bzw. — wenn ich falsch lag — Protokoll des eigenen Probe-Fehlers.

Probe-Dateien (alle lauffähig, `node research/review9-independent/<file>`):

| Datei | Fläche |
|---|---|
| `probe-issued-at.js` | issued_at-Grammatik, Kalender, Grenzwerte, Offset-Schreibweisen, Refusal-Reihenfolge, Protokoll-Erzeugnis |
| `probe-live.js` | Live-Socket: Future-Bound, Guard-Konsum, Replay, Window-Cap, `__proto__`, Tiefe, Journal-Shape, Consumer-Interop |
| `probe-ledger.js` | Window-Arithmetik (u64/Grenzen), Scope-Domänen tx↔msg, Replay/Truncate/Re-Chain, gesiegelter Floor |
| `probe-envelope.js` | Envelope-Verwechslung (body↔wire↔beides), Grant-Shape-Poisoning, Seal-MAC/Anchor gegen History-Ersatz |
| `probe-canonical.js` | JS↔Python Bytegleichheit (31 feindliche Werte), Key-Reihenfolge-Divergenz, Number-Typen, Kosten |
| `probe-client-consumer.js` | Client-Helper-Vertrag, Umkehr-Asymmetrie der echten Verifier, Feed-Sortierung |

## Befunde

### R9-1 (MINOR, gefixt): der 24h-Future-Bound ist um bis zu 999,999 ms
### aufnahmeseitig — die Fraktionssekunden werden verworfen

- **Erwartung** (findings-first, H2): `+24h+1ms` → `refuse:issued_at_in_future`.
- **Gemessen** (eingefrorene Uhr `now = 1970-01-01T00:00:00.000Z`,
  Bound = `1970-01-02T00:00:00.000Z`, `probe-issued-at.js` H2):

  | issued_at | vor Fix | nach Fix |
  |---|---|---|
  | `1970-01-02T00:00:00Z` (= +24h exakt) | ALLOW | ALLOW (Grenze inklusiv) |
  | `1970-01-02T00:00:00.001Z` (+1 ms) | **ALLOW** (Verletzung) | refuse:issued_at_in_future |
  | `1970-01-02T00:00:00.999Z` (+999 ms) | **ALLOW** (Verletzung) | refuse:issued_at_in_future |
  | `1970-01-02T00:00:00.999999Z` (+999,999 ms) | **ALLOW** (Verletzung) | refuse:issued_at_in_future |
  | `1970-01-02T00:00:00.001+00:00` (Offset-Variante) | **ALLOW** (Verletzung) | refuse:issued_at_in_future |
  | `1970-01-02T00:00:01Z` (+1 s) | refuse:issued_at_in_future | refuse:issued_at_in_future |

- **Ursache**: `issuedAtMs()` montierte den Instant mit
  `setUTCHours(hour, minute, second, 0)` (`src/policy-message.js:127` in
  `5770b59`) — der Regex-Teil `(?:\.\d{1,6})?` war nicht als Gruppe
  gefasst und wurde nie ausgewertet. Der Vergleich
  `issuedAtInstant > nowMs + MAX_FUTURE_SKEW_MS` (`src/policy-message.js:275`)
  lief damit auf den ASTRUNGEN des Moments, während der SIGNIERTEN Bytes die
  volle Schreibweise enthielt: der Bound war bis zu 999,999 ms zu lasch.
- **Schweregrad MINOR, nicht höher, weil**: der Effekt ist sub-sekundlich
  (999,999 ms bei dokumentierter 24-h-Toleranz); der Zielfall der Toleranz
  (Daily-Runner +21,4 h) liegt 2,6 h von der Grenze entfernt; kein Replay-,
  kein Key-, kein Forge-Effekt. Es ist die Verletzung eines explizit
  dokumentierten Vertrags („refused beyond now + 24h"), die der Review #7
  selbst eingeführt hat — dort war die Klasse „Format-Check, kein
  Semantik-Check" gefunden, aber nur die Sekunden-Ebene semantisch gemacht
  worden.
- **Fix** (`src/policy-message.js`): Die Fraktion ist jetzt eine gefangene
  Regex-Gruppe; `issuedAtMs()` liefert `{ ms, us }` (Instant auf
  Millisekunden + übrige Mikrosekunden 0…999999); der Bound vergleicht exakt:
  `ms > boundMs || (ms === boundMs && us > 0)`. Keine Rundung in keine
  Richtung — die Grenze ist auf das Mikrosekunden-Niveau, das die Grammatik
  zulässt, exakt. Erwartet/gehalten: mikrosekundengenau, kein Restfenster
  (verifiziert durch die 4 R9-1-Tests).

### R9-2 (LOW, gefixt): `buildReceiptBody` baute eine Antwort, die der Daemon
### immer ablehnt

- **Erwartung** (findings-first, H11): `buildReceiptBody()` ohne `issuedAt`
  → Policy-Verdict `envelope` (der Daemon verlangt `issued_at` seit
  `84888d4`).
- **Gemessen**: `refused=envelope` (probe-client-consumer, H11); mit
  explizitem `issuedAt` → `ALLOW` (H11b).
- **Einordnung**: `src/client.js:71` (in `5770b59`) machte `issued_at` zum
  Opt-in (`if (typeof issuedAt === 'string')`), während `84888d4` es
  Pflicht machte. Der Helper ist exportierte API dieses Repos (JSDoc führt
  `issued_at` als gebautes Feld, ohne es als Pflicht zu markieren); ein
  Aufrufer, der der Signatur und dem Dokumentationsstil folgt, bekommt einen
  Körper, den der Daemon mit `envelope` ablehnt. Kein Signature-Leak
  (fail-closed), daher LOW.
- **Fix** (`src/client.js`): `issued_at` ist jetzt immer vorhanden — bei
  fehlendem `issuedAt` wird wie `receipt.py` („default: now") auf die aktuelle
  UTC-Zeit gestempelt (`…+00:00`-Schreibweise), ein expliziter Wert wird
  wörtlich übernommen (Daily-Runner-Stempel, Backdate, Offset-Schreibweise).
  JSDoc erklärt den Grund und den Bezug zu `84888d4`.

### Gehalten (gemessen, kein Befund)

Die folgenden Klassen habe ich eigenständig angegriffen; alle Verdicts
gehalten. Zahlen sind MEINE Messung, nicht übernommen:

1. **issued_at-Grammatik/Kalender** (`probe-issued-at.js` H3/H4/H5):
   Schaltjahr `2028-02-29` ALLOW, `2027-02-29`/`1900-02-29`/`2100-02-29`
   (Jahrhundertregel) `refuse:envelope`, `2000-02-29` (400er-Regel) ALLOW,
   `2026-02-30`/`2026-04-31`/`2026-13-01` `refuse:envelope`, Sprungsekunde
   `:60` `refuse:envelope`, `+24:00` `refuse:envelope`, `+23:59`/`-00:00`/
   `+14:00` ALLOW (grammatiklegal, dokumentierte Grenze). Alle 9 Fälle wie
   erwartet.
2. **Offset-Schreibweisen desselben Moments** (H3): `Z`/`+02:00`/`-06:00`
   desselben Instants → identischer Verdict, aber **unterschiedliche
   Byte-Längen** (155 vs. 160) → getrennte Replay-Identitäten. Absicht:
   Bytes sind die Message. (H1c.)
3. **Kanonisierung JS↔Python** (`probe-canonical.js`): **31/31 feindliche
   Werte byte-identisch** mit `python3 json.dumps(..., sort_keys=True,
   separators=(',',':'))` — Steuerzeichen, DEL, `"`/`\`, `/`, NBSP,
   U+2028/2029, BOM, Zero-Width, kombinierende Zeichen, RTL, Astral-Emoji,
   `\\ud800`-Fluchtschreibweise, Lone-Surrogate, gemischte Strings.
   Die abstrakte Sortier-Divergenz EXISTIERT (JS UTF-16-Code-Einheiten vs.
   Python Code-Punkte: `[1d400, ffff]` vs. `[ffff, 1d400]`), ist aber über
   die Policy NICHT ERREICHBAR: Claim-Keys müssen `NAME` (ASCII) matchen
   (`refuse:claims`, gemessen). Das ist der Punkt, an dem diese Klasse
   kippen würde, wenn jemand die Key-Regex lockert — dort steht der
   explizite Warnhinweis.
4. **Number-Typen** (`probe-canonical.js`): 1e21, `-0`, `42.0`, bool, null,
   verschachteltes Objekt, Array als Claim-VALUE → alle `refuse:claims`;
   `note`/`issued_at` als Zahl → `refuse:envelope`; negativer/exponent-
   schreibender Claim-Key → `refuse:claims`. Alle Value-Slots sind
   String-getypt, daher erreicht kein Number-Fall die kanonischen Bytes.
   (`1e21` als KEY ist ASCII und damit NAME-konform — erlaubt BY DESIGN,
   weil nur Strings sortiert werden; als String-Key bytegleich.)
5. **`__proto__`/`constructor`** (H8): eigene `__proto__`-Property im Body →
   `refuse:envelope` ohne Throw; in Claims → `refuse:claims` ohne Throw.
   Live über den Socket bestätigt, Daemon bedient danach weiter
   (`probe-live.js`).
6. **Verschachtelungstiefe** (H9, live): Arrays in 4096-Zeichen-Rahmen bis
   Tiefe 2040 (4081 Zeichen) → `refuse:invalid_body`, Daemon lebt danach
   (weitere Signaturen möglich). Der Daemon-Frame-Cap greift vor jeder
   Rekursion in der Canonicalize-Funktion; kein Stack-Overflow erreichbar.
7. **Window-Cap-Arithmetik** (H13, `probe-ledger.js`): Cap greift exakt bei
   `max+1` (`ok,ok,ok,window_cap` bei max=3); `windowMaxMessages =
   9007199254740991` (MAX_SAFE_INTEGER) akzeptiert und zählt korrekt
   (`remaining = max − prior − 1`, exakt gemessen); `9007199254740992`
   → `refuse:invalid_grant_window` (kein Integer-Overflow, weil über
   `BigInt > BigInt(MAX_SAFE_INTEGER)` abgefangen); absurde
   `windowSeconds` (×1000 über safe-integer) → `cutoff = -Infinity` →
   alle Records zählen, also Richtung „Cap greift früher" (konservativ,
   H13d).
8. **Scope-Domänen** (H15): fast erschöpftes tx-Fenster (495 000 von
   10 000 000 Lamports Rest) berührt das Message-Fenster NICHT
   (`msg=1/5`); Message-Records kosten das tx-Fenster exakt 0
   (`spent = 9500000+5000+1+5000 = 9510001`, ohne die Message-Records);
   dieselben Bytes im anderen Envelope sind eine separate Identität
   (kein False-Replay); Message-Replay vom Ledger selbst `refuse:replay`.
   Live: 10/10 Journal-Records tragen einen 4-part `msg\0`-Scope.
9. **Envelope-Verwechslung** (live, `probe-envelope.js`): Message-Body auf
   tx-Grant → `grant_kind_mismatch`; tx-Wire auf Message-Grant →
   `grant_kind_mismatch`; Wire+Body in EINEM Frame (roher Socket, weil der
   `request()`-Helper ohnehin entweder/oder wählt) → `request_invalid`;
   danach signiert der Message-Grant weiter. Grant-Shape-Attacken:
   `kind:message` mit tx-Feldern → `grant_unknown_field`; fehlende `pubkey`
   → `grant_field_invalid`; `kind:tx` → `grant_field_invalid`; `kind`
   weggelassen → fällt in die tx-Validierung → `grant_unknown_field`;
   `maxBytes 9999` → `grant_field_invalid`; `windowSeconds:'0'` →
   `grant_field_invalid`; das valide Grant lädt. 6/6 wie erwartet.
10. **Journal Replay/Truncate/Re-Chain** (`probe-ledger.js`,
    `probe-envelope.js`): UNGESIEGELT: das Abschneiden des letzten Records
    lädt als kürzere Chain (**dokumentierte Grenze des unsealed Modus** —
    die Chain allein sieht keine Trunkierung, jeder Präfix ist eine gültige
    Chain) und ein korrekt daran verknüpftes, erfundenes Record wird
    akzeptiert (gleiche Grenze: nur der Seal-Floor sieht es). GESIEGELT:
    History-Ersatz durch einen Angreifer OHNE Passphrase →
    `ledger_anchor_mismatch`; Trunkierung auf 0 Records →
    `ledger_mac_short`. Beide wie erwartet — der „Truncate gegen das
    Journal"-Angriff schlägt nur im dokumentierten unsealed Modus durch,
    und dort ist er der bekannte Scope (der Seal ist der dafür
    eingeführte).
11. **Grant-Expiry-Kopien** (H16c): `expiryMs` in `policy-message.js`,
    `ledger.js` (tx) und `ledger.js` (approveMessage) verhalten sich
    identisch auf Stichprobe (canonical round trip): `2030…`/`…00Z` ALLOW,
    `2020…` `refuse:expired`, `2026-02-30`/`2026-13-01`
    `refuse:invalid_grant`.
12. **Refusal-Reihenfolge** (H16): Körper > Cap mit BAD `issued_at` →
    `refuse:message_too_large` (Cap vor Shape, wie im Code dokumentiert);
    kleiner Körper mit BAD `issued_at` → `refuse:envelope`.
13. **Consumer-Interop live** (`probe-live.js`): beide echten
    openreceipts-Verifier akzeptieren ein daemon-signiertes Artefakt —
    `receipt.py verify` exit 0 (`OK release/auroraxo/signerd issued …`),
    `verify.mjs` exit 0, gepinnt gegen den Daemon-Key.

### Umkehr-Asymmetrie: was die Verifier tun, was der Daemon verweigert

`probe-client-consumer.js` — dieselben Körper, signiert mit einem
WEGWERF-LOKALSCHLÜSSEL (kein Repo-Key, kein Daemon), damit die Verifier
überhaupt prüfen können, was sie tun würden:

| Body | Daemon-Verdict | `receipt.py verify` | `verify.mjs` |
|---|---|---|---|
| kein `issued_at` | refuse:envelope | **exit 1, `KeyError: 'issued_at'`** | **exit 0**, „issued undefined" |
| `2026-02-30…` | refuse:envelope | exit 0, „OK … issued 2026-02-30" | exit 0 |
| `+99:99`-Offset | refuse:envelope | exit 0 | exit 0 |
| `3000-01-01…` | refuse:issued_at_in_future | exit 0 | exit 0 |
| `not-a-date` | refuse:envelope | exit 0 | exit 0 |
| `1900-01-01…` (weit in der Vergangenheit) | **ALLOW** (Backdating absichtlich) | exit 0 | exit 0 |

- **Asymmetrie-Richtung: der Daemon ist die STRENGERE Seite (fail-closed),
  die Verifier sind lasch.** Das ist die sichere Richtung: kein Daemon-ver-
  signiertes Artefakt wird von einem Verifier abgelehnt (Interop-Test 13
  grün), und jeder Verifier-akzeptierte Müll ist nur mit einem lokalen
  Schlüssel erzeugbar, nicht über die Envelope.
- **Offene Baustelle beim CONSUMER (nicht in diesem Repo, daher nicht
  gefixt, hier nur gemessen)**: die Verifier haben KEINE Semantikprüfung
  („issued 2026-02-30 … OK"), und `receipt.py verify` CRASHHT (exit 1)
  statt höflich abzulehnen, wenn `issued_at` fehlt — die von Review #7
  gefundene Crash-Klasse lebt im Verifier weiter, nur nicht mehr durch die
  Envelope erzeugbar. Empfehlung: Verifier prüfen `issued_at`-Grammatik
  (gleiche Regex wie `issuedAtMs`) und geben `FAIL` statt `KeyError`.
- **H12d — Feed-Sortierung (Consumer-seitig, MINOR)**: `feed.py:67` sortiert
  nach dem `issued_at`-STRING. Gemessen: `2026-12-31T23:00:00+00:00`
  (23:00Z) vs. `2027-01-01T05:00:00+05:30` (= 23:30Z, 30 MIN Später) —
  die String-Sortierung stellt den SPÄTEREN zuerst. Die Daemon-Policy
  erlaubt grammar-gültige Offsets (bewusst, RFC3339), erzeugt also
  Artefakte, die im Feed falsch einsortiert werden können. Kein
  Sicherheitsverlust (Signaturen sind unabhängig), aber eine
  Darstellungs-Verzerrung; Fix gehört nach openreceipts (als
  `datetime.fromisoformat`-Sortierung).

### Ehrliche Protokollierung eigener Probe-Fehler

Meine Messkette hat sechs eigene Fehler ergeben, alle VOR der Endfassung
gefunden und im Probe-Code als Kommentar dokumentiert („probe bug, found and
fixed") — sie sind NICHT als Produktbefunde verkauft worden:

1. **H2-Erstversuch**: `.replace(/\.\d{3}Z$/,'Z')` löschte die
   Millisekunden und machte „+1ms" zur Grenz-Schreibweise — der Probe maß
   sein eigenes Regex. Ersetzt durch deterministische eingefrorene
   Grenzfälle.
2. **H4-Erstversuch**: eingefroren `now=2030`, aber Grant-`expiresAt` blieb
   beim echten Jetzt → ALLE Fälle `refuse:expired` vor der Kalenderprüfung.
   Grant läuft jetzt mit der eingefrorenen Uhr mit.
3. **Live-Probe Fenster-Erschöpfung**: EIN Grant mit 5 Slots für ALLE
   Checks — die Cap-Prüfung leerte ihn, die folgenden „Daemon lebt
   weiter"-Checks wurden fälschlich `window_cap`. Jetzt breites Haupt-Grant
   + eigene Cap-Instanz.
4. **Ledger H13b**: Erwartungswert fest eingetippt, dabei zwei Aspekte
   übersehen (drei Vorgänger-Records im selben Scope, eigener Slot der
   Prüfung) — zweimal; jetzt aus dem Ledger-Snapshot ABGELEITET statt
   eingetippt. H15b analog: tx-Gebühr des zweiten Transfers vergessen
   (`9500501` statt `9510001`), Erwartung jetzt `amount+fee`-Summe.
5. **Forge-Test mit falschem Hash**: ich hatte `sha256(JSON.stringify(body))`
   statt `chainHash(lastHash, body)` genommen und damit nur „kaputte Chain
   wird abgelehnt" bewiesen — die schwache Behauptung. Der ehrliche Angriff
   (korrekt verknüpftes, erfundenes Record) ist jetzt drin, mit dem
   dokumentierten Ergebnis (unsealed: akzeptiert = Limit; sealed:
   `ledger_anchor_mismatch`).
6. **`wire`+`body` über den `request()`-Helper**: der Helper wählt
   entweder/oder, der Daemon wurde nie gefragt. Neu über einen rohen
   Socket.
7. **Kanonisierungs-Erwartungen ohne `refuse:`-Präfix**: jede korrekte
   Verweigerung sah aus wie eine Verletzung (Formatierungsfehler meiner
   Assertion, nicht der Sache).

Zusätzlich zwei Umgebungs-/Unabhängigkeits-Offenlegungen:

- Beim `git worktree list` war sichtbar, dass ein Worktree
  `/tmp/signerd-boundary` auf Branch `fix/issued-at-fraction-precision`
  liegt (vermutlich aus einer früheren Sitzung). **Der Diff/Inhalt wurde
  nicht gelesen** — auch nicht nach dem Schreiben von `findings-first.md`.
  Die Existenz des Branch-Namens ließ sich nicht unwissen; die
  Grenzwert-Findings R9-1 entstammen meinem eigenen Code-Lesen
  (`setUTCHours(…, 0)` in `src/policy-message.js`) und meinen eigenen
  eingefrorenen Messungen.
- Der Auftrags-Commit `84888d4` zeigte `research/review7-envelope/*`
  INLINE (git show); ein vollständig unbekannter Erstkontakt war damit
  nicht gegeben. Meine Hypothesen stammen aus dem Code-Lesen; die
  Alt-Reports `review5/`, `review6*`, `review8-r7diff/` wurden vor
  `findings-first.md` NICHT geöffnet (siehe „Abgleich" unten).

## Ladder (Falsifikation der Fixes)

Testdatei: `test/review9-independent.test.js`, 15 Tests = 5 Fixes
(4× R9-1 + 1× R9-2) + 6 Wächter + 4 Review-7-Regressionen.

| Baum | rot | grün | Wer ist rot |
|---|---|---|---|
| **20140e9** (Parent von 84888d4, Worktree `/tmp/signerd-review9-prefix`) | **8** | **7** | 4× R9-1 (kein Bound existiert: `+1ms`…`+1s` alle ALLOW) + 4× Review-7-Regression (Fix fehlt: 2030/Feb30/+99:99/fehlendes issued_at → ALLOW) |
| **5770b59** (vor MEINEN Fixes, Worktree `/tmp/signerd-review9-5770`) | **5** | **10** | **genau meine 2 Befunde**: 4× R9-1 (Sub-Sekunden-Überlauf) + 1× R9-2 (Helper ohne issuedAt) |
| **independent/envelope-review** (nach Fix) | **0** | **15** | — |

- Die 4 Review-7-Regressionen sind auf 20140e9 rot und ab 5770b59 grün —
  sie bewachen, dass der Fix aus Review #7 in MEINEM Patch nicht
  zurückfallen.
- **False-Positive-Wachter** (müssen auf BEIDEN Vor-Bäumen grün sein, damit
  ein Patch nicht „grün" wird, indem er kaputt macht): die 6 Guards —
  exakt `+24h` erlaubt (Grenze inklusiv), gemessener Consumer-Stempel
  `+21,4h` erlaubt, Vergangenheitsstempel mit und ohne Fraktion erlaubt,
  Backdate `1900` erlaubt, Helper mit explizitem `issuedAt` erlaubt,
  kanonische Bytes eines expliziten Körpers unverändert. Gemessen grün auf
  20140e9 (7/7 Guard-Treffer unter den 7 grünen) und auf 5770b59 (10 grün
  = 6 Guards + 4 Review-7-Regressionen).
- Nummern exakt: 20140e9 = 7 pass / 8 fail (15 Tests); 5770b59 = 10 pass /
  5 fail; nach Fix = 15 pass / 0 fail.

## Verifikation nach Fix

| Prüfung | Ergebnis |
|---|---|
| `npm test` (voll) | **201/201 pass**, 0 fail, 33,6 s (Baseline 186/186 + 15 neue) |
| `npm run test:crash` (unsealed, 25 Iterationen) | **pass** (1/1), 12,4 s |
| `npm run test:crash:sealed` | **pass** |
| `probe-issued-at.js` | 14/14 PASS (vor Fix: 1 VIOLATION) |
| `probe-live.js` | 16/16 PASS (inkl. beide openreceipts-Verifier) |
| `probe-ledger.js` | 10/10 PASS |
| `probe-envelope.js` | 7/7 PASS |
| `probe-canonical.js` | 4/4 PASS + Kostenzeile |
| `probe-client-consumer.js` | 4/4 PASS (H12d Consumer-Befund als PASS der Behauptung) |

## Kostenmessung

`evaluateMessage`, Happy Path, Blocks von 20 000 Iterationen.

**Interleaved A/B in EINEM Prozess** (9 Runden, gleiche Umgebung, abwechselnd
pre/post — die belastbare Messung):

- `5770b59` (vor Fix): 25,06 25,00 30,77 25,97 26,79 28,93 25,39 30,31
  25,23 → **Median 25,97 µs/op**
- nach Fix: 24,14 27,75 20,31 22,58 23,49 27,08 31,40 28,14 28,63 →
  **Median 27,08 µs/op**
- **Delta Median: +1,11 µs/op** (≈ +4 % des Policy-Aufrufs; die
  Einzelläufe beider Varianten überlappen breit, 20,3–31,4 µs, d. h. das
  Delta liegt nahe am Messrauschen).

Getrennte Läufe (nur zur Einordnung, zwischen dem Review-7-Wert 25,3 µs):
vor Fix 24,56 µs (Median aus 7×20k), nach Fix 28,62 µs (Median aus 5×20k),
pre-review-7 (20140e9) 26,72 µs (Median aus 5×20k). Die Streuung zwischen
den Durchgängen (±4 µs) ist größer als das A/B-Delta — deshalb ist die
interleavte Zahl die hier zitierbare.

- Einordnung: +1,11 µs pro Anfrage ≈ 0,004 % der gemessenen Live-Roundtrip-
  Zeit (~31 ms p50 im Repo) — weit unter jeder Budgetgrenze, und um
  Größenordnungen kleiner als der Ledger-fsync. Kein Regressionsrisiko für
  den Daily-Runner.

## Was dieses Review NICHT abdeckt

- **Kein Audit, keine Fremdnutzung, keine echten Keys.** Alles lief mit
  Wegwerf-Ed25519-Keys in `mkdtemp`-Verzeichnissen; „ALLOW" ist ein
  Policy-Verdict, KEINE Freigabe für einen produktiven Schlüssel mit
  Bestand. Ein einzelner Reviewer ersetzt keine externe Audit-Firma.
- **Die Verifier-Semantik selbst** (`receipt.py verify`, `verify.mjs`,
  `feed.py`) liegt in `~/github_repos/openreceipts` — ich habe sie GEMESSEN
  (Asymmetrie-Tabelle oben), aber NICHT gefixt; Schreiben in ein fremdes
  Repo war nicht beauftragt.
- **Syscall-/Side-Channel-Sicherheit**: keine Timing-, keine
  `fsync`-Reihenfolgen-, keine Cache-Attacken-Prüfung. Die
  Kostenmessung ist Durchsatz, kein Timing-Modell.
- **System-Uhrsprünge live**: absichtlich nicht simuliert (keine
  Zeitraffer-/Faketime-Tests im Auftrag). Die Grenzwert-Messungen laufen
  mit der EINGEFRORENEN `now`-Parameter-Übergabe der Policy — das ist die
  deterministische Entsprechung, aber sie prüft NICHT das Verhalten bei
  echtem NTP-Sprung zwischen Daemon-Start und Anfrage. Bekannte
  Randwirkung (dokumentiert): Ein Rücksprung verkleinert die Window-
  Budgetberechnung nie (Records aus der Zukunft zählen mit), ein
  Vorwärtssprung kann Records aus dem Window fallen lassen — für die
  TX- und Message-Pfade identisch, unverändert durch meinen Patch.
- **Sealed-Modus-Attacken mit gestohlenem Passphrase**: außerhalb des
  Modells (ein Angreifer mit dem Seal-Passphrase und Schreibzugriff ist
  der Operator).
- **Nicht geprüft**: Protokoll-/Persistenzmigration (`signerd migrate`),
  der TX-Pfad jenseits der Scope-Disjunktion (review1–6 sind zuständig),
  Netzwerk-Attacken (Unix-Socket, `chmod 0700`-Verzeichnisse — von mir
  nur übernommen, nicht neu geprüft), Symlink-/Lease-Rennen in
  `grantfile.js`/`journalseal.js` (Review-5/6-Fläche).
- **Der generierte `probe-findings.json` und die `research/consumer-live-*`
  Läufe** wurden nicht erneut ausgeführt.
- **Skalierung**: alle Live-Probes sind Einzelanfragen über einen Socket;
  keine Last-/Verbindungsflut-Prüfung (Frame-Cap `8704` und Reap-Timer
  nur aus dem Code gelesen, nicht gemessen).
- **Nicht bewertet**: die Frage, ob die 24-h-Toleranz selbst die richtige
  Zahl ist (Review #7 hat sie gegen den Daily-Runner gemessen; ich habe nur
  ihre EXAKTHEIT geprüft, nicht ihre Höhe).

## Abgleich mit den Alt-Reports

Gelesen NACH `findings-first.md` (Commit `a2b3cd3`): `research/review6-report.md`,
`research/review7-envelope/report.md`, `research/review8-r7diff/report.md` sowie
die Probe-Verzeichnisse `research/review5/` und `research/review6/`
(`research/review5/` enthält KEINEN report.md, nur Probes — dort habe ich die
Probe-Namen und Zwecke gesichtet, nicht die bodies der früheren Reviews
nachgeahmt).

**Überlappung (bewusst markiert):**

- Die Review-7-Flächen `issued_at`-Semantik (`issuedAtMs`) und der
  24h-Future-Bound SIND mein Hauptschauplatz — Review #7 hatte die Klasse
  „Format-Check ohne Semantik" und „unbeschränkte Future-Datierung"
  SELBST GEFUNDEN UND GEFIXT (R7-2/R7-3), aber nur auf SEKUNDEN-Ebene:
  die Fraktion wurde verworfen, das Sub-Sekunden-Fenster blieb. Mein
  R9-1 ist die Nachfolge-Findung an der von Review #7 nicht geschlossenen
  Stelle — gemessen, nicht aus dem Alt-Report abgeleitet (der Report nennt
  das Fenster nirgends).
- **R9-2 (`buildReceiptBody`)** taucht in keinem Alt-Report auf (eigene
  Findung).
- **Review 8** (`review8-r7diff`) bewertete den DIFF von `84888d4` und kam
  zu keinem neuen Befund (nur Probes/Halter). Meine Grenzwert-Messung ist
  eine neue, andere Methode (eingefrorene Uhr) am selben Patch.
  **Gegenüberstellung der Lücke (nach dem Lesen von
  `review8-r7diff/report.md` verifiziert):** Review 8 führt „fractional
  seconds 1–6 digits" explizit als GRAMMAR-Fall (also: akzeptiert) — der
  Future-Bound wurde dort auf Tages-Ebene behandelt, nicht in
  Millisekunden. Der gemessene Sub-Sekunden-Überlauf (R9-1) taucht dort
  NICHT auf; Review 8 maß „hostile-clock handling" (Date-Subclass →
  `invalid_clock`), nicht die Auflösung des Vergleichs. Mein R9-1 schließt
  also genau die Stelle, die Review 8 als „gehalten" markiert hat, ohne die
  Restauflösung zu prüfen.
- **Überlappung mit Review 8, Abschnitt „Replay amplification by spelling":**
  Review 8 hat (unabhängig von mir) gemessen, dass 5 Schreibweisen DESSELBEN
  Moments 5 verschiedene Bodies und damit 5 Window-Slots ergeben. Ich habe
  dieselbe Klasse berührt (H1c: 155 vs. 160 Bytes, getrennte Replay-Identität)
  und komme zum selben Schluss: Kapazitäts-, keine Autorisierungs-
  Amplifikation. **Gleiche Klasse, gleiche Schlussfolgerung, unabhängig
  gemessen** — kein neuer Befund meinerseits.
- **Kanonisierung 31/31** (ich) vs. **10/10** (Review 7, anderer Satz):
  gleiche Konklusion, verschiedene Stichproben — Überlappung der METHODIK,
  nicht der Zahlen.
- **Scope-Disjunktion/Window-Arithmetik**: Review 7 „held", ich „held"
  mit eigenen Zahlen (9510001 statt ihrer 20400-Pinierung). Doppelte
  Messung, unabhängige Zahlen.
- **Journal-Truncation**: Review 6 (`c1117ae`, R5-2/R6) hat den Seal-Floor
  eingeführt; mein „unsealed akzeptiert Truncation" ist die BESTÄTIGUNG des
  dokumentierten Limits (nicht neu, aber unabhängig gemessen),
  „sealed verweigert `ledger_anchor_mismatch`/`ledger_mac_short`" ist meine
  eigene Messung.
- **Consumer-Crash (`KeyError: 'issued_at'`)**: R7-1 von Review 7 gefunden;
  ich habe die Verifier-Asymmetrie UNABHÄNGIG neu gemessen (gleiche
  Erkenntnis, und der Crash lebt im Verifier weiter — Empfehlung an
  openreceipts, nicht gefixt).

**Nicht überlappend (ausschließlich meine Findung):** R9-1, R9-2, H12d
(Feed-Sortierung), die 7 eigenen Probe-Fehler, die abstrakte
Sortier-Divergenz mit ihrem Erreichbarkeits-Nachweis (31/31 + `refuse:claims`).

## Änderungen auf diesem Branch (nicht gepusht)

| Datei | Inhalt |
|---|---|
| `src/policy-message.js` | R9-1: Fraktions-Gruppe im Regex, `issuedAtMs` → `{ms, us}`, exakter Bound-Vergleich |
| `src/client.js` | R9-2: `issued_at` immer vorhanden (Default = jetzt, wie `receipt.py`) |
| `test/review9-independent.test.js` | 15 Tests: 5 rot-auf-Vor-Baum + 6 Wächter + 4 Review-7-Regressionen |
| `research/review9-independent/findings-first.md` | Erstbefunde vor Messung (Commit `a2b3cd3`) |
| `research/review9-independent/helper.js` + 6 `probe-*.js` | eigenes Fixture + lauffähige Probes |
| `research/review9-independent/report.md` | dieser Report |

Kein Push, kein Merge — der Parent verifiziert.
