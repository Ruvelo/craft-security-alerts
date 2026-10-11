<?php

declare(strict_types=1);

namespace ruvelo\securityalerts\jobs;

use Craft;
use craft\queue\BaseJob;
use ruvelo\securityalerts\exceptions\SourceException;
use ruvelo\securityalerts\Plugin;
use yii\queue\RetryableJobInterface;

/**
 * Runs a security check from the queue.
 */
class CheckJob extends BaseJob implements RetryableJobInterface
{
    private const MAX_ATTEMPTS = 3;

    public function execute($queue): void
    {
        Plugin::getInstance()?->getChecker()->run();
    }

    public function getTtr(): int
    {
        return 120;
    }

    public function canRetry(mixed $attempt, mixed $error): bool
    {
        return $error instanceof SourceException && $attempt < self::MAX_ATTEMPTS;
    }

    protected function defaultDescription(): ?string
    {
        return Craft::t('security-alerts', 'Checking for known vulnerabilities');
    }
}
