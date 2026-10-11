<?php

declare(strict_types=1);

namespace ruvelo\securityalerts\models;

class CheckOutcome
{
    /**
     * @param int $emailed Findings put in an email
     */
    public function __construct(
        public readonly ScanResult $result,
        public readonly Changes $changes,
        public readonly int $emailed,
    ) {
    }
}
