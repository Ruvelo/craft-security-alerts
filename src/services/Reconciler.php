<?php

declare(strict_types=1);

namespace ruvelo\securityalerts\services;

use LogicException;
use Ruvelo\SecurityAdvisories\Finding as CoreFinding;
use Ruvelo\SecurityAdvisories\Reconciler as CoreReconciler;
use ruvelo\securityalerts\models\Changes;
use ruvelo\securityalerts\models\Finding;
use ruvelo\securityalerts\models\ScanResult;

/**
 * Compares a fresh scan with what is stored, so that only what changed counts as news.
 *
 * What counts as the same finding is the core's call: a stored row is recognised by its key, its
 * CVE and its aliases, so the same vulnerability named differently by another source is neither
 * new nor resolved. The row keeps the advisory id it was first stored under.
 */
class Reconciler
{
    public function __construct(
        private readonly FindingStoreInterface $store,
        private readonly CoreReconciler $core = new CoreReconciler(),
    ) {
    }

    public function reconcile(ScanResult $result): Changes
    {
        $report = $result->report ?? throw new LogicException('Only a result from a scan can be reconciled.');

        $rows = [];
        $known = [];
        $lastSeen = [];
        foreach ($this->store->all() as $row) {
            $rows[$row->coreKey()] = $row;
            $known[$row->coreKey()] = $row->exploited;
            $lastSeen[$row->coreKey()] = $row->toCoreArray();
        }

        $changes = $this->core->reconcile($known, $report, $lastSeen);
        $next = $this->core->next($known, $report, [], $lastSeen);
        $seen = $this->core->lastSeen($lastSeen, $report, $next);

        $current = [];
        foreach ($report->findings as $finding) {
            $current[$finding->key()] = $finding;
        }

        $new = [];
        $becameExploited = [];
        foreach (array_keys($next) as $key) {
            $found = $current[$seen[$key]['key'] ?? ''] ?? null;
            if (!$found instanceof CoreFinding) {
                continue; // Not vouched for this time: left as it was.
            }
            $finding = Finding::fromCore($found);
            $row = $rows[$key] ?? null;

            if ($row === null) {
                $this->store->insert($finding);
                $new[] = $finding;
                continue;
            }

            // Once exploited, always exploited: the CISA list can be briefly unreachable, and a
            // missing answer must not quietly lower the alarm.
            $exploited = $finding->exploited || $row->exploited;
            $merged = new Finding(
                $row->package,
                $finding->installedVersion,
                $row->advisoryId,
                $finding->title,
                $finding->link,
                $finding->cve,
                $finding->severity,
                $finding->fixedIn,
                $exploited,
                $row->id,
                $row->firstSeenAt,
                $finding->fixedAfter,
                $finding->aliases,
            );
            $this->store->update($merged);
            if ($exploited && !$row->exploited) {
                $becameExploited[] = $merged;
            }
        }

        $resolved = 0;
        foreach ($rows as $key => $row) {
            if ($row->id === null || array_key_exists($key, $next)) {
                continue;
            }
            $this->store->delete($row->id);
            if (in_array($key, $changes->resolved, true)) {
                $resolved++;
            } // else: two rows for one vulnerability collapsed into the first, and the other is closed quietly.
        }

        return new Changes($new, $becameExploited, $resolved);
    }
}
