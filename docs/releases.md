# Quarterly release checklist

Target a release every three months (January, April, July, and October). The owner prepares and publishes each release; the calendar is a target, not a reason to ship with unresolved security issues.

1. Review changes and security reports; update the changelog and version.
2. Run the GitHub Actions security workflow on the release commit.
3. Confirm there are no new third-party dependencies, secrets, or scan reports in the release.
4. Create an annotated `vX.Y.Z` tag and publish GitHub release notes.
5. Confirm the release page and attached source archive are correct.

The workflow runs on pushes and pull requests. GitHub Actions scheduled runs can be delayed, so a calendar reminder is more reliable for the quarterly preparation date. Do not configure unattended publication of releases.
