#!/usr/bin/env python3
"""Local, read-only security posture checks for personal computers."""

from __future__ import annotations

import argparse
import datetime as dt
import json
import platform
import shutil
import subprocess
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Optional


@dataclass
class Check:
    name: str
    status: str  # pass, attention, unknown
    weight: int
    summary: str
    recommendation: str


def run_readonly(args: list[str], timeout: int = 8) -> Optional[str]:
    """Run a fixed OS query without a shell; return None when unavailable."""
    try:
        result = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if result.returncode != 0:
        return None
    return result.stdout.strip()


def powershell(script: str) -> Optional[str]:
    exe = shutil.which("powershell") or shutil.which("pwsh")
    if not exe:
        return None
    return run_readonly([exe, "-NoProfile", "-NonInteractive", "-Command", script])


def windows_checks() -> list[Check]:
    checks: list[Check] = []
    firewall = powershell(
        "(Get-NetFirewallProfile -ErrorAction Stop | Where-Object {$_.Enabled -eq $false} | Measure-Object).Count"
    )
    if firewall is None:
        checks.append(Check("Firewall", "unknown", 20, "Could not read Windows Firewall status.", "Open Windows Security and confirm the firewall is on for all network profiles."))
    elif firewall == "0":
        checks.append(Check("Firewall", "pass", 20, "Windows Firewall is enabled for all detected profiles.", "Keep the firewall enabled."))
    else:
        checks.append(Check("Firewall", "attention", 20, "At least one Windows Firewall profile is disabled.", "Enable the firewall for domain, private, and public networks."))

    defender = powershell(
        "$s=Get-MpComputerStatus -ErrorAction Stop; if ($s.AMServiceEnabled -and $s.RealTimeProtectionEnabled) {'pass'} else {'attention'}"
    )
    if defender is None:
        checks.append(Check("Built-in antivirus", "unknown", 20, "Could not read Microsoft Defender real-time protection status.", "In Windows Security, confirm that active antivirus protection is running."))
    elif defender == "pass":
        checks.append(Check("Built-in antivirus", "pass", 20, "Microsoft Defender reports real-time protection enabled.", "Keep protection and signatures up to date."))
    else:
        checks.append(Check("Built-in antivirus", "attention", 20, "Microsoft Defender reports real-time protection disabled.", "Enable real-time protection or confirm another trusted antivirus is active."))

    encryption = powershell(
        "$v=Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction Stop; if ($v.ProtectionStatus -eq 'On') {'pass'} else {'attention'}"
    )
    if encryption is None:
        checks.append(Check("System drive encryption", "unknown", 20, "Could not verify BitLocker protection for the system drive.", "Check Device Encryption or BitLocker in Windows Settings. Save the recovery key securely."))
    elif encryption == "pass":
        checks.append(Check("System drive encryption", "pass", 20, "BitLocker reports protection enabled for the system drive.", "Keep the recovery key somewhere separate from this device."))
    else:
        checks.append(Check("System drive encryption", "attention", 20, "BitLocker protection is not enabled for the system drive.", "Consider enabling Device Encryption or BitLocker and securely storing the recovery key."))

    latest = powershell(
        "$h=Get-HotFix -ErrorAction Stop | Sort-Object InstalledOn -Descending | Select-Object -First 1; if ($h.InstalledOn) {$h.InstalledOn.ToString('yyyy-MM-dd')}"
    )
    checks.append(update_check(latest))
    return checks


def unix_checks() -> list[Check]:
    system = platform.system()
    checks: list[Check] = []
    if system == "Linux":
        fw = None
        ufw = shutil.which("ufw")
        if ufw:
            fw = run_readonly([ufw, "status"])
            if fw is not None:
                fw = "pass" if "Status: active" in fw else "attention"
        if fw is None and shutil.which("firewall-cmd"):
            state = run_readonly([shutil.which("firewall-cmd") or "firewall-cmd", "--state"])
            fw = "pass" if state == "running" else ("attention" if state is not None else None)
        if fw is None:
            checks.append(Check("Firewall", "unknown", 20, "Could not determine whether a host firewall is active.", "Check your distribution's firewall settings (for example, UFW or firewalld)."))
        elif fw == "pass":
            checks.append(Check("Firewall", "pass", 20, "A supported Linux firewall reports active.", "Keep firewall rules enabled and reviewed."))
        else:
            checks.append(Check("Firewall", "attention", 20, "A supported Linux firewall reports inactive.", "Enable and configure the host firewall for your distribution."))

        lsblk = shutil.which("lsblk")
        output = run_readonly([lsblk, "-o", "TYPE"] if lsblk else ["/nonexistent"])
        if output is None:
            checks.append(Check("Disk encryption", "unknown", 20, "Could not inspect block-device types.", "Check whether full-disk encryption was enabled during installation."))
        elif "crypt" in output.lower():
            checks.append(Check("Disk encryption", "pass", 20, "A dm-crypt device is present; this does not prove every disk is encrypted.", "Confirm the system and data volumes are covered and protect recovery material."))
        else:
            checks.append(Check("Disk encryption", "unknown", 20, "No dm-crypt device was identified; other encryption methods may be in use.", "Check the encryption status of the system and data volumes."))
    elif system == "Darwin":
        fw = run_readonly(["/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate"])
        if fw is None:
            checks.append(Check("Firewall", "unknown", 20, "Could not read macOS Application Firewall status.", "Check System Settings → Network → Firewall."))
        else:
            active = "enabled" in fw.lower() and "disabled" not in fw.lower()
            checks.append(Check("Firewall", "pass" if active else "attention", 20, "macOS Application Firewall reports " + ("enabled." if active else "disabled."), "Keep the firewall enabled unless you have a specific managed configuration."))
        fv = run_readonly(["fdesetup", "status"])
        if fv is None:
            checks.append(Check("Disk encryption", "unknown", 20, "Could not read FileVault status.", "Check Privacy & Security → FileVault."))
        else:
            active = "filevault is on" in fv.lower()
            checks.append(Check("Disk encryption", "pass" if active else "attention", 20, fv, "Enable FileVault and keep recovery information secure."))
    else:
        checks.append(Check("Firewall", "unknown", 20, f"Checks are not implemented for {system}.", "Review the operating system's firewall settings."))
        checks.append(Check("Disk encryption", "unknown", 20, f"Checks are not implemented for {system}.", "Review the operating system's full-disk encryption settings."))

    checks.append(Check("Operating system updates", "unknown", 20, "This platform's update age could not be verified reliably without a package-specific update source.", "Install pending operating-system security updates from the official system updater."))
    checks.append(Check("Malware protection", "unknown", 20, "This version does not query third-party or platform malware protection on this system.", "Confirm trusted, supported malware protection is enabled."))
    return checks


def update_check(value: Optional[str]) -> Check:
    if not value:
        return Check("Operating system updates", "unknown", 20, "Could not determine the most recently installed Windows update.", "Check Windows Update and install pending security updates.")
    try:
        installed = dt.date.fromisoformat(value)
        age = (dt.date.today() - installed).days
    except ValueError:
        return Check("Operating system updates", "unknown", 20, "The last update date could not be interpreted.", "Check Windows Update and install pending security updates.")
    if age <= 90:
        return Check("Operating system updates", "pass", 20, f"The latest listed hotfix was installed {age} days ago ({value}).", "Check Windows Update regularly; this check does not confirm every update is installed.")
    return Check("Operating system updates", "attention", 20, f"The latest listed hotfix is {age} days old ({value}).", "Check Windows Update for pending security updates.")


def make_report() -> dict:
    system = platform.system()
    checks = windows_checks() if system == "Windows" else unix_checks()
    total = sum(c.weight for c in checks)
    penalty = sum(c.weight for c in checks if c.status == "attention")
    score = round(100 * (total - penalty) / total) if total else 0
    return {
        "tool": "DeviceSentinel",
        "version": "0.1.0",
        "generated_at": dt.datetime.now().astimezone().isoformat(timespec="seconds"),
        "device": {"os": system, "release": platform.release(), "architecture": platform.machine()},
        "risk_score": score,
        "score_note": "Heuristic posture score, not a probability of compromise. Unknown checks are excluded from penalties.",
        "checks": [asdict(c) for c in checks],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Run local, read-only security posture checks.")
    sub = parser.add_subparsers(dest="command", required=True)
    scan = sub.add_parser("scan", help="Check selected operating-system security controls")
    scan.add_argument("--json", metavar="PATH", help="also save a JSON report to this path")
    args = parser.parse_args()
    report = make_report()
    print(f"DeviceSentinel {report['version']} — {report['device']['os']} {report['device']['release']}")
    print(f"Posture score: {report['risk_score']}/100")
    print("This is not a malware scan or proof that the device is uncompromised.\n")
    for check in report["checks"]:
        print(f"[{check['status'].upper():9}] {check['name']}: {check['summary']}")
        if check["status"] != "pass":
            print(f"            Suggested action: {check['recommendation']}")
    if args.json:
        path = Path(args.json).expanduser()
        try:
            path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        except OSError as exc:
            print(f"Could not write report: {exc}", file=sys.stderr)
            return 2
        print(f"\nJSON report saved to {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
