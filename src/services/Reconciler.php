<?php

declare(strict_types=1);

namespace ruvelo\securityalerts\services;

use ruvelo\securityalerts\models\Changes;
use ruvelo\securityalerts\models\Finding;

/**
 * Compares a fresh scan with what is stored, so that only what changed counts as news.
 */
class Reconciler
{
    public function __construct(private readonly FindingStoreInterface $store)
    {
    }

    /**
     * @param list<Finding> $current
     */
    public function reconcile(array $current): Changes
    {
        $stored = [];
        foreach ($this->store->all() as $row) {
            $stored[$row->key()] = $row;
        }

        $new = [];
        $becameExploited = [];
        $seen = [];
        foreach ($current as $finding) {
            $seen[$finding->key()] = true;
            $known = $stored[$finding->key()] ?? null;
            if ($known === null) {
                $this->store->insert($finding);
                $new[] = $finding;
                continue;
            }
            // Once exploited, always exploited: the CISA list can be briefly unreachable, and a
            // missing answer must not quietly lower the alarm.
            $exploited = $finding->exploited || $known->exploited;
            $merged = $finding->withExploited($exploited);
            $this->store->update($merged);
            if ($exploited && !$known->exploited) {
                $becameExploited[] = $merged;
            }
        }

        $resolved = 0;
        foreach ($stored as $key => $row) {
            if (!isset($seen[$key]) && $row->id !== null) {
                $this->store->delete($row->id);
                $resolved++;
            }
        }

        return new Changes($new, $becameExploited, $resolved);
    }
}
