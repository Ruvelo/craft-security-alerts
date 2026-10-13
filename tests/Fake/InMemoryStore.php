<?php

declare(strict_types=1);

namespace ruvelo\securityalerts\tests\Fake;

use ruvelo\securityalerts\models\Finding;
use ruvelo\securityalerts\services\FindingStoreInterface;

/**
 * Behaves like the database table, in an array.
 */
class InMemoryStore implements FindingStoreInterface
{
    /** @var array<int, array{finding: Finding, notified: bool, notified_exploited: bool}> */
    public array $rows = [];

    private int $next = 1;

    public function all(): array
    {
        return array_values(array_map(static fn(array $r): Finding => $r['finding'], $this->rows));
    }

    public function insert(Finding $finding): void
    {
        $id = $this->next++;
        $this->rows[$id] = [
            'finding' => $this->with($finding, $id),
            'notified' => false,
            'notified_exploited' => false,
        ];
    }

    /**
     * A row as an earlier release left it: stored, and already told to whoever was to be told.
     */
    public function seed(Finding $finding, bool $notified = true): void
    {
        $id = $this->next++;
        $this->rows[$id] = [
            'finding' => $this->with($finding, $id),
            'notified' => $notified,
            'notified_exploited' => $notified && $finding->exploited,
        ];
    }

    public function update(Finding $finding): void
    {
        foreach ($this->rows as $id => $row) {
            if ($row['finding']->key() === $finding->key()) {
                $this->rows[$id]['finding'] = $this->with($finding, $id);
            }
        }
    }

    public function delete(int $id): void
    {
        unset($this->rows[$id]);
    }

    public function pendingNotification(): array
    {
        $pending = [];
        foreach ($this->rows as $row) {
            $f = $row['finding'];
            if (!$row['notified'] || ($f->exploited && !$row['notified_exploited'])) {
                $pending[] = $f;
            }
        }

        return $pending;
    }

    public function markNotified(array $findings): void
    {
        foreach ($findings as $f) {
            if ($f->id !== null && isset($this->rows[$f->id])) {
                $this->rows[$f->id] = [
                    'finding' => $this->rows[$f->id]['finding'],
                    'notified' => true,
                    'notified_exploited' => $f->exploited,
                ];
            }
        }
    }

    private function with(Finding $f, int $id): Finding
    {
        return new Finding(
            $f->package,
            $f->installedVersion,
            $f->advisoryId,
            $f->title,
            $f->link,
            $f->cve,
            $f->severity,
            $f->fixedIn,
            $f->exploited,
            $id,
            '2026-10-12 00:00:00',
            $f->fixedAfter,
            $f->aliases,
        );
    }
}
