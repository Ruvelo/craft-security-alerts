<?php

declare(strict_types=1);

namespace ruvelo\securityalerts\models;

use Craft;
use craft\base\Model;
use craft\helpers\App;
use Ruvelo\SecurityAdvisories\Scanner as Core;

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
     * Where advisories come from: "valtry" asks Valtry's signed Advisory API first (package names only, never versions)
     * and uses the public feeds whenever it cannot answer; "public" never contacts Valtry.
     * RUVELO_ADVISORIES_SOURCE=public in the environment wins over this setting.
     */
    public string $advisorySource = SourceLabel::VALTRY;

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
     * Whether Valtry is never contacted: the setting says so, or the environment does (and it wins).
     */
    public function usesPublicFeedsOnly(): bool
    {
        return Core::source($this->advisorySource) === Core::SOURCE_PUBLIC;
    }

    /**
     * Whether the environment alone keeps every request off Valtry, whatever the setting says.
     */
    public static function sourceIsForcedPublic(): bool
    {
        return Core::source(SourceLabel::VALTRY) === Core::SOURCE_PUBLIC;
    }

    /**
     * @return array<string, string> Source value => label
     */
    public static function sourceOptions(): array
    {
        return [
            SourceLabel::VALTRY => Craft::t('security-alerts', 'Valtry (default)'),
            SourceLabel::PUBLIC => Craft::t('security-alerts', 'Public feeds only'),
        ];
    }

    /**
     * @return array<int|string, mixed>
     */
    protected function defineRules(): array
    {
        $rules = parent::defineRules();
        $rules[] = [['enabled', 'checkOnCpUse'], 'boolean'];
        $rules[] = [['minimumSeverity'], 'in', 'range' => array_map(static fn(Severity $s): string => $s->value, Severity::cases())];
        $rules[] = [['advisorySource'], 'in', 'range' => array_keys(self::sourceOptions())];
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
