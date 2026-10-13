<?php

declare(strict_types=1);

namespace ruvelo\securityalerts\migrations;

use craft\db\Migration;
use ruvelo\securityalerts\services\FindingStore;
use ruvelo\securityalerts\services\State;

class Install extends Migration
{
    public function safeUp(): bool
    {
        $this->createTable(FindingStore::TABLE, [
            'id' => $this->primaryKey(),
            'package' => $this->string(255)->notNull(),
            'advisoryId' => $this->string(64)->notNull(),
            'installedVersion' => $this->string(128)->notNull(),
            'title' => $this->text()->notNull(),
            'link' => $this->text(),
            'cve' => $this->string(32),
            'severity' => $this->string(16),
            'fixedIn' => $this->string(128),
            'fixedAfter' => $this->string(128),
            'aliases' => $this->text(),
            'exploited' => $this->boolean()->notNull()->defaultValue(false),
            'notified' => $this->boolean()->notNull()->defaultValue(false),
            'notifiedExploited' => $this->boolean()->notNull()->defaultValue(false),
            'dateCreated' => $this->dateTime()->notNull(),
            'dateUpdated' => $this->dateTime()->notNull(),
            'uid' => $this->uid(),
        ]);
        $this->createIndex(null, FindingStore::TABLE, ['package', 'advisoryId'], true);
        $this->createIndex(null, FindingStore::TABLE, ['exploited']);

        $this->createTable(State::TABLE, [
            'id' => $this->primaryKey(),
            'name' => $this->string(64)->notNull(),
            'value' => $this->text()->notNull(),
            'dateCreated' => $this->dateTime()->notNull(),
            'dateUpdated' => $this->dateTime()->notNull(),
            'uid' => $this->uid(),
        ]);
        $this->createIndex(null, State::TABLE, ['name'], true);

        return true;
    }

    public function safeDown(): bool
    {
        $this->dropTableIfExists(State::TABLE);
        $this->dropTableIfExists(FindingStore::TABLE);

        return true;
    }
}
