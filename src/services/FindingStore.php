<?php

declare(strict_types=1);

namespace ruvelo\securityalerts\services;

use craft\db\Query;
use craft\helpers\Db;
use ruvelo\securityalerts\models\Finding;

/**
 * Findings in the plugin's own table.
 */
class FindingStore implements FindingStoreInterface
{
    public const TABLE = '{{%securityalerts_findings}}';

    public function all(): array
    {
        return $this->hydrate($this->query()->all());
    }

    public function insert(Finding $finding): void
    {
        Db::insert(self::TABLE, [
            'package' => $finding->package,
            'advisoryId' => $finding->advisoryId,
            'installedVersion' => $finding->installedVersion,
            'title' => $finding->title,
            'link' => $finding->link,
            'cve' => $finding->cve,
            'severity' => $finding->severity,
            'fixedIn' => $finding->fixedIn,
            'fixedAfter' => $finding->fixedAfter,
            'exploited' => $finding->exploited,
            'notified' => false,
            'notifiedExploited' => false,
        ]);
    }

    public function update(Finding $finding): void
    {
        Db::update(self::TABLE, [
            'installedVersion' => $finding->installedVersion,
            'title' => $finding->title,
            'link' => $finding->link,
            'cve' => $finding->cve,
            'severity' => $finding->severity,
            'fixedIn' => $finding->fixedIn,
            'fixedAfter' => $finding->fixedAfter,
            'exploited' => $finding->exploited,
        ], [
            'package' => $finding->package,
            'advisoryId' => $finding->advisoryId,
        ]);
    }

    public function delete(int $id): void
    {
        Db::delete(self::TABLE, ['id' => $id]);
    }

    public function pendingNotification(): array
    {
        return $this->hydrate(
            $this->query()
                ->where(['notified' => false])
                ->orWhere(['and', ['exploited' => true], ['notifiedExploited' => false]])
                ->all(),
        );
    }

    public function markNotified(array $findings): void
    {
        foreach ($findings as $finding) {
            if ($finding->id !== null) {
                Db::update(self::TABLE, [
                    'notified' => true,
                    'notifiedExploited' => $finding->exploited,
                ], ['id' => $finding->id]);
            }
        }
    }

    /**
     * @return Query<int, array<string, mixed>>
     */
    private function query(): Query
    {
        return (new Query())->from(self::TABLE)->orderBy(['id' => SORT_ASC]);
    }

    /**
     * @param array<int, array<string, mixed>> $rows
     * @return list<Finding>
     */
    private function hydrate(array $rows): array
    {
        return array_values(array_map(static fn(array $r): Finding => new Finding(
            (string)$r['package'],
            (string)$r['installedVersion'],
            (string)$r['advisoryId'],
            (string)$r['title'],
            $r['link'] !== null ? (string)$r['link'] : null,
            $r['cve'] !== null ? (string)$r['cve'] : null,
            $r['severity'] !== null ? (string)$r['severity'] : null,
            $r['fixedIn'] !== null ? (string)$r['fixedIn'] : null,
            (bool)$r['exploited'],
            (int)$r['id'],
            (string)$r['dateCreated'],
            $r['fixedAfter'] !== null ? (string)$r['fixedAfter'] : null,
        ), $rows));
    }
}
