<div align="center">
  <img src="https://raw.githubusercontent.com/Centinell2025/the-last-evidence-standing/main/branding/BEACON_SEAL.png" alt="Beacon of the Eagle LLC — logotipo corporativo" width="165" />
  <p><strong>BEACON OF THE EAGLE LLC</strong><br/><strong>CENTINELL SUITE DEFENSE</strong></p>
</div>

# The Ghost in the Kernel

**HTB Sherlock candidate | Target difficulty: Insane | Category: DFIR**

Advanced simulated Windows investigation into process visibility discrepancies, persistence, log manipulation, and correlated lateral movement.

**Development status: NOT READY FOR HTB SUBMISSION.**

## Planned investigation
1. Validate source provenance and timestamps.
2. Investigate Windows services, processes, and scheduled tasks.
3. Correlate suspicious host events and memory-process listings.
4. Assess telemetry gaps against benign possibilities.
5. Analyze network flows for cross-host activity.
6. Reconstruct the incident with exact artifact references.

## Proposed player files
- `PLAYER-INSTRUCTIONS.md`
- `evidence/host_a/process_events.csv`
- `evidence/host_a/services.csv`
- `evidence/host_a/memory_views.csv`
- `evidence/host_b/security_events.csv`
- `evidence/network/flows.csv`
- `evidence/hashes.sha256`

## Quality gates
- [ ] Generate complete, internally consistent synthetic evidence
- [ ] Create 20 hard, evidence-grounded questions
- [ ] Validate each answer and eliminate ambiguity
- [ ] Conduct clean-room walkthrough
- [ ] Package player-only ZIP with password `hackthebox`
- [ ] Keep the instructor writeup private

All organizations, accounts, and network addresses are fictional. No real malware or client data.
