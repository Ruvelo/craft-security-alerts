<?php

declare(strict_types=1);

namespace ruvelo\securityalerts\models;

use Craft;
use craft\base\Model;
use craft\helpers\App;

/**
 * Plugin settings. They live in project config, so they travel with the rest of the site's config.
 */
class Settings extends Model
{
    /** Turns off email and the optional check-on-CP-use. The console command and "Check now" still work. */
    public bool $enabled = true;

    /** Who to email: addresses separated by commas, spaces or new lines. Environment variables work. Empty means control panel only. */
    public string $emails = '';

    /** Lowest severity that is emailed. Exploited findings are always emailed. */
    public string $minimumSeverity = 'medium';

    /** When no cron job runs the console command, check at most once a day when someone uses the control panel. */
    public bool $checkOnCpUse = false;

    /**
     * @return list<string> Valid addresses only
     */
    public function recipients(): array
    {
        $parsed = App::parseEnv($this->emails);
        $addresses = preg_split('/[\s,;]+/', is_string($parsed) ? $parsed : '', -1, PREG_SPLIT_NO_EMPTY) ?: [];

        return array_values(array_unique(array_filter(
            $addresses,
            static fn(string $a): bool => filter_var($a, FILTER_VALIDATE_EMAIL) !== false,
        )));
    }

    public function minimum(): Severity
    {
        return Severity::tryFrom($this->minimumSeverity) ?? Severity::Medium;
    }

    /**
     * @return array<string, string> Severity value => label
     */
    public static function severityOptions(): array
    {
        $options = [];
        foreach (Severity::cases() as $severity) {
            $options[$severity->value] = Craft::t('security-alerts', $severity->label());
        }

        return $options;
    }

    /**
     * @return array<int|string, mixed>
     */
    protected function defineRules(): array
    {
        $rules = parent::defineRules();
        $rules[] = [['enabled', 'checkOnCpUse'], 'boolean'];
        $rules[] = [['minimumSeverity'], 'in', 'range' => array_map(static fn(Severity $s): string => $s->value, Severity::cases())];
        $rules[] = [['emails'], 'string', 'max' => 2000];
        $rules[] = [['emails'], function(string $attribute): void {
            $parsed = App::parseEnv($this->emails);
            $given = preg_split('/[\s,;]+/', is_string($parsed) ? $parsed : '', -1, PREG_SPLIT_NO_EMPTY) ?: [];
            $invalid = array_values(array_filter(
                $given,
                static fn(string $a): bool => filter_var($a, FILTER_VALIDATE_EMAIL) === false,
            ));
            if ($invalid !== []) {
                $this->addError($attribute, Craft::t('security-alerts', 'These are not email addresses: {list}', [
                    'list' => implode(', ', $invalid),
                ]));
            }
        }];

        return $rules;
    }
}
