THE GHOST IN THE KERNEL — FORENSIC INVESTIGATION PACKAGE
Author and publisher: BEACON OF THE EAGLE LLC · CENTINELL SUITE DEFENSE
Target HTB difficulty: INSANE CANDIDATE — NOT CERTIFIED/ACCEPTED
Fictional case: Northbridge Systems / NB-KERN-2026-0917

1. Verify the archive integrity:
     cd artifacts && sha256sum -c SHA256SUMS.txt
2. Read PLAYER-INSTRUCTIONS.md and docs/FORENSIC_SCOPE.md.
3. Open questions/INVESTIGATION.md and solve all 20 exact-value tasks.
4. Use Python 3, a spreadsheet/CSV viewer and SQLite CLI or DB Browser.
5. Example read-only analysis:
     sqlite3 'file:artifacts/timeline_cache.sqlite3?mode=ro' '.schema'
6. All evidence is synthetic. No EVTX, RAM dump, real malware, customer PII,
   validated rootkit, authenticated telemetry, or production attack is included.
   Do not execute unknown binaries or infer a real actor from a service account.

The public generator repository is NOT a fair substitute for this ZIP in blind
playtesting. Instructor solutions must be provided separately and privately.
© 2026 Beacon of the Eagle LLC · Centinell Suite Defense.
