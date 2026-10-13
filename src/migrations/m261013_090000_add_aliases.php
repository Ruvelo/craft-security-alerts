<?php

declare(strict_types=1);

namespace ruvelo\securityalerts\migrations;

use craft\db\Migration;
use ruvelo\securityalerts\services\FindingStore;
use yii\db\Schema;

/**
 * 1.1.0: findings keep the other ids they are known by, so a finding stays the same finding when
 * a different source names it. Additive: 1.0 rows get no aliases and are recognised by their id and CVE.
 */
class m261013_090000_add_aliases extends Migration
{
    public function safeUp(): bool
    {
        // A fresh install already has the column (the install migration creates the final table).
        if (!$this->db->columnExists(FindingStore::TABLE, 'aliases')) {
            $this->addColumn(FindingStore::TABLE, 'aliases', Schema::TYPE_TEXT);
        }

        return true;
    }

    public function safeDown(): bool
    {
        if ($this->db->columnExists(FindingStore::TABLE, 'aliases')) {
            $this->dropColumn(FindingStore::TABLE, 'aliases');
        }

        return true;
    }
}
