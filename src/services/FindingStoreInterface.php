<?php

declare(strict_types=1);

namespace ruvelo\securityalerts\services;

use ruvelo\securityalerts\models\Finding;

/**
 * Where seen findings are kept between checks.
 */
interface FindingStoreInterface
{
    /**
     * @return list<Finding> Every stored finding
     */
    public function all(): array;

    public function insert(Finding $finding): void;

    /**
     * Refreshes the installed version, the advisory details and the exploited flag of a stored finding.
     */
    public function update(Finding $finding): void;

    public function delete(int $id): void;

    /**
     * Findings nobody has been told about yet, or that became exploited after the last email.
     *
     * @return list<Finding>
     */
    public function pendingNotification(): array;

    /**
     * @param list<Finding> $findings
     */
    public function markNotified(array $findings): void;
}
