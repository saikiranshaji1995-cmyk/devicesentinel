# Security policy

## Scope and limits

DeviceSentinel checks a small number of security settings on the computer where it runs. It is not antivirus software, an incident response tool, or proof that a device is uncompromised. False positives and missed threats are possible.

## Reporting a vulnerability

Please report suspected vulnerabilities privately to the repository owner using GitHub's private vulnerability reporting feature when available. Include the affected version, steps to reproduce, and impact. Do not include secrets, personal data, or unredacted scan reports in a public issue.

## Data handling

Scans run locally. DeviceSentinel makes no network requests and does not read user documents, browser data, passwords, or file contents. JSON reports are written only to the path explicitly supplied by the user. The owner should review changes for unintended data collection before each release.

## Release security checks

Before publishing each release, the maintainer should review the diff, run the security workflow, inspect dependencies (currently none), verify the tag and release notes, and confirm that no credentials or personal scan reports are included.
