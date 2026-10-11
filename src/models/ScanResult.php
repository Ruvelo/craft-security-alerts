<?php

declare(strict_types=1);

namespace ruvelo\securityalerts\models;

class ScanResult
{
    /**
     * @param list<Finding> $findings Exploited first, then by severity
     * @param list<string> $warnings Things that did not work but did not stop the check
     */
    public function __construct(
        public readonly array $findings,
        public readonly array $warnings,
        public readonly int $packagesChecked,
    ) {
    }

    /**
     * @return list<Finding>
     */
    public function exploited(): array
    {
        return array_values(array_filter($this->findings, static fn(Finding $f): bool => $f->exploited));
    }
}
