<div align="center">
  <img src="https://raw.githubusercontent.com/Centinell2025/the-last-evidence-standing/main/branding/BEACON_SEAL.png" alt="Beacon of the Eagle LLC — logotipo corporativo" width="165" />
  <p><strong>BEACON OF THE EAGLE LLC</strong><br/><strong>CENTINELL SUITE DEFENSE</strong></p>
</div>

# The Ghost in the Kernel

**Hack The Box Sherlock candidate · Windows DFIR · Target difficulty: Insane (NOT externally validated)**

A fictional Northbridge Systems analyst investigates conflicting process visibility, a service-account logon, scheduled-task and service activity, a disputed software-policy change, and cross-host network telemetry. The challenge teaches reproducible source correlation **without falsely claiming that a kernel rootkit, lateral execution or exfiltration has been proven**.

## Current development status

**Playable synthetic student evidence with automatic QA; instructor grading and independent blind tests still pending.** The evidence generator provides CSV Windows-style excerpts, deterministic SHA-256 policy specimens, a real SQLite analysis cache, background decoys and an acquisition-scope register. No real EVTX, memory image, malware or production data are bundled.

## How to obtain the student package

1. Open [GitHub Actions](https://github.com/Centinell2025/The-Ghost-in-the-Kernel/actions/workflows/validate.yml).
2. Open the newest successful run and download its `ghost-kernel-student` artifact.
3. Unzip the workflow download, then extract `The-Ghost-in-the-Kernel-STUDENT.zip`.
4. Read `README.txt`, `PLAYER-INSTRUCTIONS.md`, `docs/FORENSIC_SCOPE.md` and the [20 investigation questions](questions/INVESTIGATION.md).
5. Verify `artifacts/SHA256SUMS.txt` before working.

To reproduce locally with Python 3 (no external packages):

```bash
python3 tools/build_lab.py
python3 tools/verify_lab.py
python3 -m unittest discover -s tests -v
python3 tools/build_student_zip.py
```

## Quality / examiner restrictions

- The 20 exact-answer tasks must have a **confidential instructor-only answer key and demonstrated write-up** before formal submission.
- Two experienced investigators should cold-solve **only the student ZIP**, not this public generator repository, to measure difficulty and ambiguity.
- Absence from API enumeration is **not proof of kernel hiding** without real independently acquired memory and kernel observations.
- A reported TCP flow **does not prove complete session coverage, payload content, malicious purpose or exfiltration**.

All organizations, identities, events, addresses and data are simulated. © 2026 **Beacon of the Eagle LLC — Centinell Suite Defense**. The corporate seal identifies authorship only, not external accreditation or proof of a real incident.
