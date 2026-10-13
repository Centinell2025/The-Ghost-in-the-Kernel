# The Ghost in the Kernel — 20 investigation questions

**Case:** NB-KERN-2026-0917 · **Target:** Insane candidate (unverified) · **All evidence fictional.**

Each answer requires a precise evidence citation. Record UTC timestamps with a trailing `Z`. Read the provenance limitations before claiming a kernel compromise.

## Stage 1 — Identity and privilege

**Q01.** Which endpoint reported a successful `svc-diagnostics` session related to the process-visibility discrepancy? **Answer format:** hostname.

**Q02.** At what exact UTC timestamp was the relevant successful `4624` logon recorded, distinct from a subsequent `4672` privilege-assignment event? **Answer format:** `YYYY-MM-DDTHH:MM:SSZ`.

**Q03.** What hexadecimal logon ID joins the `4624`, `4672`, and suspicious process creation? **Answer format:** `0x...`.

**Q04.** Which service-account name is associated with that session? It does not identify the human operator. **Answer format:** exact account name.

## Stage 2 — Process and visibility

**Q05.** Which PID appears in the process-create export but is missing in the later API enumeration sample? Join across both sources. **Answer format:** decimal PID.

**Q06.** What is the **direct parent PID** of that process, not the network client that it later spawned? **Answer format:** decimal PID.

**Q07.** Which process-create event ID records the disputed PID? **Answer format:** `PROC-NNN`.

**Q08.** What precise scheduled-task path was registered immediately before the sampled execution, and references the same executable as the service? **Answer format:** full Windows task path.

**Q09.** Which Windows service name points to the implicated executable? **Answer format:** service name.

**Q10.** Which process-visibility event ID shows `absent-from-sample`, not the historical process-create observation? **Answer format:** `VIEW-NNN`.

## Stage 3 — Policy integrity and change approval

**Q11.** Which file-integrity event ID shows a changed policy specimen? **Answer format:** `FIM-NNN`.

**Q12.** Recompute SHA-256 from the actual bytes of `observed_policy.bin` and reconcile it with `file_integrity.csv`. What is the digest? **Answer format:** 64 lowercase hexadecimal characters.

**Q13.** Which denied unsigned maintenance ticket contradicts the local routine-update hypothesis? Exclude the approved decoy. **Answer format:** `CHG-NNN`.

## Stage 4 — File-server and network evidence

**Q14.** When did the secondary file server first record a successful `svc-diagnostics` logon from the gateway's address? **Answer format:** `YYYY-MM-DDTHH:MM:SSZ`.

**Q15.** Which DNS hostname resolves to the destination of the implicated TCP flow? **Answer format:** hostname ending in `.example`.

**Q16.** Which destination TCP port is recorded in the flow summary for that correlation? **Answer format:** decimal port.

**Q17.** How many outbound bytes does that flow summary *claim*? Distinguish the claim from independently captured content. **Answer format:** decimal bytes.

**Q18.** Which PID belongs to the spawned network client process, not the parent service? **Answer format:** decimal PID.

## Stage 5 — Timing and evidentiary limits

**Q19.** The `sysmon_process.csv` clock is documented as 30 seconds ahead of actual UTC. Normalize the recorded `PROC-711` timestamp (central estimate). **Answer format:** `YYYY-MM-DDTHH:MM:SSZ`.

**Q20.** Does this collection prove actual kernel-level process hiding or a rootkit? **Answer format:** `ESTABLISHED` or `NOT ESTABLISHED`.

## Senior DFIR assessment — separately human graded

Submit an evidence-cited timeline, a source-dependency matrix and a 400–700 word incident commander memorandum addressing **WHAT, WHERE, WHEN, HOW, WHY, WHO is actually known, and the purpose only if justified**. Compare authorized change, anomalous local software change and kernel concealment as separate hypotheses. Explain the difference between a service account and a person; file-server authentication and lateral execution; exporter bytes and data exfiltration; scheduled-task registration and verified persistence. End with a NO-GO / CONDITIONAL-GO / GO restoration decision with verifiable acquisition gates.

**All records are synthetic. No answer key or instructor write-up appears in the student package.**
