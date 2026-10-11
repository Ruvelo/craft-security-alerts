# Contributing to Security Alerts for Craft CMS

Thanks for helping! Bug reports, false positives, docs fixes and features are all welcome.

## Before you start

- **A wrong or missing finding:** [open an issue](https://github.com/Ruvelo/craft-security-alerts/issues/new/choose) with the package, the installed version and the advisory id. Advisories come from Packagist, so one that is wrong at the source should be fixed in [FriendsOfPHP/security-advisories](https://github.com/FriendsOfPHP/security-advisories) or the GitHub advisory database too.
- **Features:** open an issue first if it is more than a small change.
- **Security issues:** don't open an issue. See [SECURITY.md](https://github.com/Ruvelo/.github/blob/main/SECURITY.md).

## Setup

You need PHP 8.2+ and Composer. The unit tests need no database and no Craft install: Craft comes in as a dev dependency, and the tests mock everything else.

```bash
git clone https://github.com/<you>/craft-security-alerts && cd craft-security-alerts
composer install
composer check
```

| Command | What it does |
|---|---|
| `composer test` | PHPUnit unit tests |
| `composer lint` | ECS with `craftcms/ecs` (`composer fix` applies fixes) |
| `composer analyse` | PHPStan level 8 with `craftcms/phpstan` |

CI also installs the plugin into a real Craft project on MySQL, runs the console command and loads the utility page. To do the same locally, create a project with `composer create-project craftcms/craft`, add this checkout as a `path` repository, and run `php craft plugin/install security-alerts`.

Tests never touch the network. Packagist and CISA answers come from the fixtures in `tests/_files/`.

## Making a change

1. Branch from `main`.
2. Write a test that fails without your change.
3. Keep the public surface stable: the console command and exit codes, settings, the permission, the event and the tables.
4. Run `composer check`.
5. Add a line to [CHANGELOG.md](CHANGELOG.md).
6. Open the pull request.

## Style

- `declare(strict_types=1)` everywhere, typed properties and return types.
- No `@phpstan-ignore` or baseline entries: fix the cause.
- Comments explain why, not what.
- Nothing in the control panel, emails or console output links anywhere but advisory pages.

By contributing you agree that your work is released under the [MIT license](LICENSE.md) and that you'll follow the [code of conduct](https://github.com/Ruvelo/.github/blob/main/CODE_OF_CONDUCT.md).
