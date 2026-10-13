# Evidence scope and evaluation — The Ghost in the Kernel

**Publisher:** Beacon of the Eagle LLC / Centinell Suite Defense  
**Incident:** fully synthetic Northbridge Systems Windows DFIR case, 2026-09-17.

## Goals

A monitoring system reports a process-visibility discrepancy on `nb-win-01`, a newly registered task, a simulated maintenance service, and activity on another host. Investigators must correlate logon ID, account, parent/child processes, scheduled tasks, file integrity, DNS and flow summaries; review the change-control contradiction; and articulate what remains unknown.

## Scientific boundaries

All artifacts are synthesized from `tools/build_lab.py`. CSVs are **not original EVTX**, `process_visibility.csv` is **not a real forensic memory image**, and `timeline_cache.sqlite3` duplicates selected records for query practice. A live-API sample not listing a process whose creation was previously logged **does not establish DKOM, a kernel rootkit or anti-forensics**: sampling windows, process exit and sensor limitations are alternate explanations. The TCP flow **does not prove content, C2 or exfiltration**.

The `acquisition_register.csv` records simulated source, completeness and lack of independent verification. All addresses use documentation networks and all DNS names are reserved `.example`.

## Suggested investigation sequence

1. Check `SHA256SUMS.txt` against the actual evidence bytes.
2. Reconstruct the source-clock-specific timeline, including its uncertainty.
3. Join the relevant 4624 logon ID to the process tree and task/service registration.
4. Compare the live API and event excerpt views without inventing kernel-level facts.
5. Recompute hashes of binary policy specimens and reconcile the integrity alert.
6. Join the second-host logon to the DNS/flow tuple; distinguish independent sources from the derived SQLite cache.
7. Compare rejected change `CHG-782` against the approved routine-change decoy.
8. Deliver an executive containment/restoration memo supported by facts and testable next acquisitions.

## Examiner readiness

The 20 tasks are exact-answer candidates. The lab **must not be advertised as HTB Insane approved** without a private instructor key, screenshots proving every response, and two non-author blind solves. A passing CI result establishes fixture consistency and archive integrity, not official difficulty.

**Corporate seal:** logo and author attribution in the GitHub README; author attribution inside the ZIP. No seal is inserted into raw evidence bytes.
