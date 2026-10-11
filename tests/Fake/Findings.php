<?php

declare(strict_types=1);

namespace ruvelo\securityalerts\tests\Fake;

use ruvelo\securityalerts\models\Finding;

class Findings
{
    public static function make(
        string $package = 'acme/craft-widgets',
        string $advisory = 'PKSA-1',
        bool $exploited = false,
        ?string $severity = 'high',
        string $installed = '1.2.0',
        string $title = 'A flaw',
    ): Finding {
        return new Finding(
            $package,
            $installed,
            $advisory,
            $title,
            'https://example.com/' . $advisory,
            'CVE-2099-' . substr($advisory, -4),
            $severity,
            '9.9.9',
            $exploited,
        );
    }
}
