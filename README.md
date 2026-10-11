<p align="center">
  <a href="#install"><strong>Install</strong></a> &nbsp;&nbsp;&nbsp;
  <a href="#running-it"><strong>Running it</strong></a> &nbsp;&nbsp;&nbsp;
  <a href="#command-line"><strong>CLI</strong></a> &nbsp;&nbsp;&nbsp;
  <a href="#events"><strong>Events</strong></a> &nbsp;&nbsp;&nbsp;
  <a href="CHANGELOG.md"><strong>Changelog</strong></a>
</p>

<p align="center">
  <a href="https://github.com/Ruvelo/craft-security-alerts/actions/workflows/tests.yml"><img src="https://github.com/Ruvelo/craft-security-alerts/actions/workflows/tests.yml/badge.svg" alt="Tests"></a>
  <img src="https://img.shields.io/badge/Craft-5.x-3d4eff" alt="Craft 5.x">
  <img src="https://img.shields.io/badge/PHP-8.2%E2%80%938.4-3d4eff" alt="PHP 8.2 to 8.4">
  <img src="https://img.shields.io/badge/PHPStan-level%208-3d4eff" alt="PHPStan level 8">
  <a href="LICENSE.md"><img src="https://img.shields.io/badge/license-MIT-3d4eff" alt="MIT license"></a>
</p>

# Security Alerts for Craft CMS

**Know before they do.** This plugin tells you, in the control panel and by email, when the exact Craft version you run, or a plugin you installed with Composer, has a known vulnerability. When the flaw is **exploited in the wild**, it says so loudly: "Exploited — patch now".

Craft's own updates screen shows what is new. It does not tell you that the version you are on is being attacked. This plugin is free, MIT licensed, and needs no account and no API key.

```
composer require ruvelo/craft-security-alerts
php craft plugin/install security-alerts
php craft security-alerts/check
```

## A quick tour

> These are screenshots of a real Craft 5.11 install with the plugin, taken with a `composer.lock` that was deliberately edited to say Craft 5.6.10 so that there is something to show. The advisories are live Packagist data, trimmed to eight rows for the picture.

<img src="art/screenshot-utility.png" alt="Utilities, Security alerts: a red banner saying two known vulnerabilities are being exploited, a Check now button and a table with the exploited findings first">

**One page, exploited first.** Utilities → Security alerts lists every finding: the package, the installed version, the advisory (a link), the CVE, the severity, an "Exploited — patch now" badge, and the fixed-in version. "Check now" runs the check straight away.

<table>
  <tr>
    <td width="50%"><img src="art/screenshot-dashboard.png" alt="The dashboard widget showing 8 open findings, 2 exploited"></td>
    <td width="50%"><img src="art/screenshot-settings.png" alt="The plugin settings, with a note on what leaves the server"></td>
  </tr>
  <tr>
    <td>A dashboard widget with the count, exploited ones highlighted.</td>
    <td>The settings say what leaves the server, right where you switch it on.</td>
  </tr>
</table>

## Features

- **Craft and plugins.** Exact versions come from your project's `composer.lock`: `craftcms/cms`, every plugin and every package they pull in, as long as Packagist lists an advisory for it.
- **Exploited in the wild, first.** Findings whose CVE is on the [CISA Known Exploited Vulnerabilities](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) list are labelled "Exploited — patch now", sorted first, and always emailed.
- **Only what is new.** Findings are stored, so you get an email for a new finding, or one that has *become* exploited, and not the same list every morning.
- **A fix version.** The first version that is not affected, followed across release lines (`5.6.x` and `4.14.x`). Some advisories only say "up to 5.6.16"; the plugin then says "later than 5.6.16".
- **Control panel, email, CLI and an event.** A utility, a dashboard widget, an email through Craft's mailer, `php craft security-alerts/check` for CI, and a Craft event for your own tooling.
- **Free sources, no keys.** Packagist's security advisories API and the CISA catalogue, both public.
- **Cheap.** A handful of HTTPS requests a day. Nothing runs on a front-end request.

Watching many sites? [Valtry](https://valtry.co.uk/?utm_source=ruvelo&utm_medium=github&utm_campaign=craft-security-alerts) checks every site from the outside, daily.

## What it sends

Only **package names** leave your server, to `packagist.org` (and, for the exploited list, a plain download from `cisa.gov`). Versions are matched on your server, so nobody learns which version you run. No site URL, no content, no user data, no account, no keys.

| Request | Sent | Why |
|---|---|---|
| `POST https://packagist.org/api/security-advisories/` | the package names from `composer.lock` | to get the advisories for them |
| `GET https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json` | nothing | to learn which CVEs are exploited |

Only runtime packages are sent: `require-dev` packages (`packages-dev` in the lock) are not, and neither are packages on a dev branch such as `dev-main`, which cannot be matched anyway. A private package from a private repository is still sent by name if it is in `packages`, and Packagist simply knows nothing about it. Your server's address is visible to Packagist and CISA, as it is for any request. Requests go through Craft's own HTTP client, so a configured proxy applies.

The plugin never installs, changes or updates anything, and only writes to its own two tables.

## Requirements

- Craft CMS 5.x on PHP 8.2 to 8.4.
- A `composer.lock` in the project root (the usual Composer install). Without one, only Craft itself is checked, and "Check now" and the CLI warn you.
- Outbound HTTPS to `packagist.org` and `www.cisa.gov`.

## Install

```bash
composer require ruvelo/craft-security-alerts
php craft plugin/install security-alerts
```

Or install it from Settings → Plugins. The install migration creates two tables, `securityalerts_findings` and `securityalerts_state`. Then run the first check:

```bash
php craft security-alerts/check
```

## Running it

Craft has no built-in scheduler, so the daily run is yours to set up. **The recommended way is a cron line** that runs the console command once a day, as the same user that runs your queue:

```cron
17 6 * * * cd /var/www/project && php craft security-alerts/check >/dev/null 2>&1
```

That checks, stores what changed, emails what is new, and fires the event. Nothing else is needed.

**No cron? Use the fallback.** Switch on "Check when the control panel is used" in the plugin settings. When someone opens the control panel and no check has run for a day, the plugin pushes one job onto Craft's queue and the control panel's queue runner executes it. It never runs a check inside the request, queues at most one job an hour while one is waiting, and does nothing for visitors of the front end. It only works on sites whose control panel is visited, and so is a second choice to cron.

"Check now" in the utility always works, whatever the settings.

## Command line

```
php craft security-alerts/check [--json] [--fail-on=exploited|any] [--dry-run]
```

| Option | What it does |
|---|---|
| *(none)* | Check, store what changed, email what is new, and print the findings |
| `--json` | Print the findings as JSON instead of text |
| `--fail-on=exploited` | Exit with code `1` if any finding is known to be exploited |
| `--fail-on=any` | Exit with code `1` if there is any finding |
| `--dry-run` | Only report: no stored changes, no email, no event |

Exit codes: `0` fine, `1` a finding matched `--fail-on`, `2` a source could not be reached or an option is wrong. For a deploy pipeline:

```bash
php craft security-alerts/check --dry-run --json --fail-on=exploited > alerts.json
```

JSON shape:

```json
{
  "exploited": 1,
  "total": 1,
  "packages_checked": 111,
  "warnings": [],
  "findings": [
    {
      "package": "craftcms/cms",
      "installed_version": "5.6.10",
      "advisory_id": "PKSA-…",
      "title": "Craft CMS Allows Remote Code Execution",
      "link": "https://github.com/advisories/GHSA-f3gw-9ww9-jmc3",
      "cve": "CVE-2025-32432",
      "severity": "critical",
      "severity_level": "critical",
      "fixed_in": null,
      "fixed_after": "5.6.16",
      "exploited": true
    }
  ]
}
```

`severity` is what Packagist reports, and may be `null`. `severity_level` is what the plugin uses: an unrated advisory counts as **high**, so that a missing rating never hides a real flaw behind the minimum-severity setting.

## Settings

Settings → Plugins → Security Alerts. They are stored in project config, so they deploy with the rest of your configuration. The email field accepts environment variables, such as `$SECURITY_ALERTS_EMAILS`.

| Setting | Default | |
|---|---|---|
| Enable | Yes | Turns off email and the check on control panel use. The console command and "Check now" still work |
| Notification emails | empty | Separate addresses with commas or new lines. Empty means control panel only |
| Minimum severity to email | Medium | Exploited findings are always emailed |
| Check when the control panel is used | No | The cron-less fallback described above |

The minimum severity is applied when a finding is first seen: a finding below it is not emailed later if you lower the setting, but it stays in the utility.

You can also set them in `config/project/project.yaml` or with `php craft project-config/set plugins.security-alerts.settings.emails ops@example.com`.

### Permission

Admins can do everything. For others, the plugin adds one permission, **View security alerts and run a check** (`securityAlerts-view`). It is needed to see the page and the widget and to press "Check now". Craft also requires its own Utilities → Security alerts permission to open the utility, so grant both.

## Events

After every check that finds something, the checker triggers `ruvelo\securityalerts\services\Checker::EVENT_FINDINGS_FOUND` with a `ruvelo\securityalerts\events\FindingsEvent`:

| Property | Type | |
|---|---|---|
| `findings` | `Finding[]` | Everything that applies right now, exploited first |
| `newFindings` | `Finding[]` | New since the last check, plus findings that just became exploited |
| `result` | `ScanResult` | Also has `warnings` and `packagesChecked` |

```php
use ruvelo\securityalerts\events\FindingsEvent;
use ruvelo\securityalerts\services\Checker;
use yii\base\Event;

Event::on(Checker::class, Checker::EVENT_FINDINGS_FOUND, function(FindingsEvent $event) {
    foreach ($event->newFindings as $finding) {
        if ($finding->exploited) {
            // $finding->package, ->installedVersion, ->cve, ->title, ->link, ->fixedIn
        }
    }
});
```

The event is not triggered for `--dry-run`, or when nothing applies.

## FAQ

**Does it send my Craft version, my URL or my content anywhere?**
No. Package names go to Packagist, and versions are matched on your server. See [What it sends](#what-it-sends).

**Does it patch anything?**
No. It tells you what to update.

**Is the list complete?**
No. It knows what Packagist's advisory database lists, and which of those CVEs CISA says are exploited. A flaw nobody has published, or that never reached Packagist, is not covered. A CVE reaches the CISA list some time after exploitation starts. It is an early warning, not a scanner: it does not look at your files, your users or your templates.

**A plugin I use is not reported, but I know it has a flaw.**
It is not in Packagist's advisories, or it is not installed through Composer, or it comes from a private repository that Packagist does not know.

**Why does it say I am affected when I backported a fix?**
Versions are what it can see. A patch applied by hand does not change `composer.lock`.

**Can I run it in CI?**
Yes: `--dry-run --json --fail-on=exploited`.

## Contributing

Pull requests are welcome. Clone, `composer install`, then `composer check` runs the code style, PHPStan level 8 and the unit tests, as CI does. You don't need a database for that. CI additionally installs the plugin into a real Craft project. See [CONTRIBUTING.md](CONTRIBUTING.md) and the [changelog](CHANGELOG.md).

## Credits

Built by [François Bultez](https://github.com/francoisbultez) at [Valtry](https://valtry.co.uk/?utm_source=ruvelo&utm_medium=github&utm_campaign=craft-security-alerts), the website security scanner, and everyone who [contributes](https://github.com/Ruvelo/craft-security-alerts/graphs/contributors).

Advisory data comes from the [Packagist security advisories API](https://packagist.org/apidoc#list-security-advisories). The list of exploited vulnerabilities is the [CISA KEV catalogue](https://www.cisa.gov/known-exploited-vulnerabilities-catalog).

## License

MIT. See [LICENSE.md](LICENSE.md).
