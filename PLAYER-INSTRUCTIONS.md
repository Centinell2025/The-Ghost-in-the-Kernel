# The Ghost in the Kernel — Investigator onboarding

**Intended difficulty:** Insane *candidate*; independent difficulty validation pending.  
**Author:** Beacon of the Eagle LLC — Centinell Suite Defense.

You have received a **standalone student ZIP**. The company, hosts, users, addresses and attack story are fictional. This is a defensive Windows investigation; you do not need administrative rights, a live Windows machine, a virtual machine or paid tooling.

Verify `artifacts/SHA256SUMS.txt` first. Investigate `nb-win-01` process visibility, a suspicious scheduled task and service, privileged `svc-diagnostics` activity, authorization anomalies and reported connections to `nb-file-02` and the edge gateway.

Analyze the CSV exhibits, binary policy specimens and SQLite analysis cache without changing their contents. Record the precise artifact and event ID supporting each response. Use the **appropriate source-clock offset**, not a blanket correction. The collected data cannot prove kernel compromise, a real actor's identity, lateral execution, data theft or post-reboot persistence. Treat these as hypotheses requiring more acquisitions.

Follow `questions/INVESTIGATION.md` sequentially. Finish with a confidence-qualified incident report and restoration conditions. The generator, tests and grading logic belong to the author's development repository and are deliberately absent from the student ZIP.
