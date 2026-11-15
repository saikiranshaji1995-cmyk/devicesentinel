# DeviceSentinel

DeviceSentinel is a local, read-only security posture checker for personal computers. It collects a small set of operating-system security signals, explains gaps, and produces a local JSON report. It does not claim to prove that a device is hacked or clean.

## Current scope

- Windows, macOS, and Linux computers (best-effort checks; some controls may be reported as unknown).
- Firewall, disk encryption, and recent operating-system update signals.
- On Windows, Microsoft Defender status where PowerShell and Defender are available.
- A transparent risk score and recommendations, calculated locally from the checks.

Phones are not scanned by this version. Android and iOS restrict the system access an ordinary app would need; phone checks are currently limited to the checklist in `docs/mobile-checklist.md`.

## Requirements

- Python 3.10 or later
- No third-party Python packages
- Some checks require administrator privileges or platform tools. Missing permissions/tools are reported as unknown.

## Run

```powershell
python devicesentinel.py scan
python devicesentinel.py scan --json report.json
```

On macOS or Linux, use `python3` if `python` is not available. The scan only reads operating-system settings and command output. It does not change settings, delete files, quarantine items, or send data over the network. Reports may include your OS version and local check results; keep them private before sharing.

## Understanding results

The score is a heuristic prioritization aid, not a probability of compromise or a malware verdict. A failed check means a security control may be off or stale. An unknown result means the check could not be performed; it is not treated as a pass. If you see signs of account theft, unexpected remote access, or financial fraud, use a trusted security professional and the relevant account provider.

DeviceSentinel currently has no cloud AI integration. Its local risk analysis is explainable and deterministic; it does not upload device data to an AI service. This keeps scans private and avoids representing a rules engine as a trained AI detector.

## Security and release process

See [SECURITY.md](SECURITY.md), [CONTRIBUTING.md](CONTRIBUTING.md), and [docs/releases.md](docs/releases.md). The project is intended to have one maintainer/contributor: the repository owner. Quarterly releases should be prepared and reviewed by the owner; do not publish a release until the security workflow passes.
