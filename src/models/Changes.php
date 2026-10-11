<?php

declare(strict_types=1);

namespace ruvelo\securityalerts\models;

class Changes
{
    /**
     * @param list<Finding> $new Findings seen for the first time
     * @param list<Finding> $becameExploited Known findings that have since been added to the CISA list
     * @param int $resolved Findings that no longer apply
     */
    public function __construct(
        public readonly array $new,
        public readonly array $becameExploited,
        public readonly int $resolved,
    ) {
    }
}
