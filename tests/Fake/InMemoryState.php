<?php

declare(strict_types=1);

namespace ruvelo\securityalerts\tests\Fake;

use ruvelo\securityalerts\services\StateInterface;

class InMemoryState implements StateInterface
{
    /** @var array<string, string> */
    public array $values = [];

    public function get(string $name): ?string
    {
        return $this->values[$name] ?? null;
    }

    public function set(string $name, string $value): void
    {
        $this->values[$name] = $value;
    }
}
