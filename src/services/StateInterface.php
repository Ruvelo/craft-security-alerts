<?php

declare(strict_types=1);

namespace ruvelo\securityalerts\services;

/**
 * A few small facts that survive between runs, such as when the last check happened.
 */
interface StateInterface
{
    public function get(string $name): ?string;

    public function set(string $name, string $value): void;
}
