<?php

declare(strict_types=1);

namespace ruvelo\securityalerts\models;

/**
 * Names the data source in plain words, for the utility page and the console. Which one answered
 * is a fact about this check, not a recommendation.
 */
class SourceLabel
{
    public const VALTRY = 'valtry';
    public const PUBLIC = 'public';
    public const MIXED = 'mixed';

    public static function long(string $source): string
    {
        return match ($source) {
            self::VALTRY => 'Valtry Advisory API (signed answers)',
            self::MIXED => 'Valtry Advisory API and the public feeds',
            default => 'public feeds (Packagist and CISA)',
        };
    }

    public static function short(string $source): string
    {
        return match ($source) {
            self::VALTRY => 'via Valtry, signed',
            self::MIXED => 'via Valtry and the public feeds',
            default => 'via public feeds',
        };
    }
}
