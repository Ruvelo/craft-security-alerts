# Release Notes for Security Alerts

## 1.0.0 - 2026-10-12

First release.

### Added
- Checks the exact installed versions of Craft (`craftcms/cms`) and every runtime package in `composer.lock` against Packagist's security advisories, matching versions locally with `composer/semver`.
- Findings on the CISA Known Exploited Vulnerabilities catalogue are marked "Exploited — patch now" and listed first.
- A "Security alerts" utility (Utilities → Security alerts) with package, installed version, advisory link, CVE, severity, an exploited badge and the fixed-in version, plus a "Check now" button.
- A dashboard widget showing the number of open findings, with exploited ones highlighted.
- The `securityAlerts-view` permission.
- Email through Craft's mailer, only for new findings and findings that became exploited.
- `php craft security-alerts/check` with `--json`, `--fail-on=exploited|any` and `--dry-run`. Exit code 1 when a finding matches `--fail-on`, 2 when a source fails.
- An optional "check when the control panel is used, at most once a day" fallback that pushes a queue job, for sites without a cron job.
- Settings: enable, notification emails, minimum severity, check on control panel use.
- The `ruvelo\securityalerts\services\Checker::EVENT_FINDINGS_FOUND` event.
