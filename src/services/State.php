<?php

declare(strict_types=1);

namespace ruvelo\securityalerts\services;

use craft\db\Query;
use craft\helpers\Db;

/**
 * Small facts kept in the plugin's own table.
 */
class State implements StateInterface
{
    public const TABLE = '{{%securityalerts_state}}';

    public function get(string $name): ?string
    {
        $value = (new Query())->select('value')->from(self::TABLE)->where(['name' => $name])->scalar();

        return is_string($value) ? $value : null;
    }

    public function set(string $name, string $value): void
    {
        Db::upsert(self::TABLE, ['name' => $name, 'value' => $value], ['value' => $value]);
    }
}
