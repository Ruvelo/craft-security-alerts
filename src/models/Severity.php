<?php

declare(strict_types=1);

namespace ruvelo\securityalerts\models;

enum Severity : string
{
    case Low = 'low';
    case Medium = 'medium';
    case High = 'high';
    case Critical = 'critical';

    /**
     * Packagist leaves some advisories unrated. Rather than let a missing rating hide a real
     * flaw behind the minimum-severity setting, an unrated advisory counts as high.
     */
    public static function fromAdvisory(?string $value): self
    {
        return $value === null ? self::High : (self::tryFrom(strtolower(trim($value))) ?? self::High);
    }

    public function rank(): int
    {
        return match ($this) {
            self::Low => 1,
            self::Medium => 2,
            self::High => 3,
            self::Critical => 4,
        };
    }

    public function label(): string
    {
        return ucfirst($this->value);
    }
}
