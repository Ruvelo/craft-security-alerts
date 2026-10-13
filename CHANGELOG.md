# Release Notes for Security Alerts

## 1.1.0 - 2026-10-13

The plugin now runs on [`ruvelo/security-advisories`](https://github.com/Ruvelo/security-advisories) ^1.1, the core shared by Ruvelo's security plugins, instead of its own copy of the lock file reading, Packagist and CISA clients and version matching. A change to how results are built now needs a core release or a data fix at the source, not a release of this plugin.

**Upgrading:** run `php craft up` (or let Craft prompt you) to apply one additive migration. Nothing is sent again: findings stored by 1.0 are recognised, so the first check after upgrading emails nothing new. **By default a check now asks Valtry's Advisory API**, which receives package names only (never versions), with signed answers and an automatic fallback to Packagist and CISA. To never contact Valtry, set **Advisory source** to **Public feeds only** in the plugin settings, or set `RUVELO_ADVISORIES_SOURCE=public` in the server's environment. Nothing else changes for the control panel, the console command, the permission, the email or the event.

### Added
- Valtry's signed Advisory API as the default source, with automatic fallback to Packagist and CISA when it is unreachable, slow, answers with an error, sends an answer that does not verify, or says its data is out of date.
- An **Advisory source** setting: **Valtry (default)** or **Public feeds only** (`advisorySource` in project config). `RUVELO_ADVISORIES_SOURCE=public` in the environment wins over it. The settings page says what is sent in each case.
- The data source on the utility page ("Data source: …"), in the console summary ("… via Valtry, signed" or "via public feeds") and as `source` and `sources` in `--json`. `ScanResult::source()` and `sourceLabel()`, and the stored `last_source`.
- Stable finding identity: a stored finding is recognised by its advisory id, its CVE and its aliases, so the same vulnerability reported under another id by another source is neither new nor resolved, and nothing is emailed twice. The new `aliases` column (migration `m261013_090000_add_aliases`) keeps the other ids.

### Changed
- Reading `composer.lock`, asking the sources, matching versions, marking exploited findings and working out what changed are done by the core. Behaviour, wording and exit codes are unchanged, including "later than X" for advisories that only name the last affected release.
- A check with any problem (a source that failed, or an unreadable CISA list) now resolves nothing, where 1.0 still resolved findings after a failed CISA download. Findings are only removed after a complete check.
- HTTP goes through Craft's own Guzzle client as a PSR-18 client (so a configured proxy still applies), and answers are cached under `storage/runtime/security-alerts`. Requests identify themselves as `ruvelo/craft-security-alerts`.
- `composer/semver` is no longer required directly; it comes with the core.

### Removed
- The plugin's own `AdvisoryMatcher`, `ComposerLock`, `AdvisoryClient`, `KevCatalogue`, `GuzzleFetcher` and `FetcherInterface`, now in the core. They were internal implementation, not part of the documented surface (the console command, settings, permission, event and tables), which is unchanged. `Finding`, `ScanResult` and `FindingsEvent` keep every property and method they had.

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
