<?php

declare(strict_types=1);

namespace ruvelo\securityalerts\services;

/**
 * Decides whether the control panel should queue a check, for sites that run no cron job.
 *
 * At most one check a day. A check that was queued but has not finished (the queue is not
 * running, say) is not queued again for an hour.
 */
class DailyTrigger
{
    public const STATE_LAST_QUEUED = 'last_queued';

    private const DAY = 86400;
    private const RETRY_AFTER = 3600;

    public function __construct(private readonly StateInterface $state)
    {
    }

    /**
     * Returns true, and records it, when a check should be queued now.
     */
    public function claim(int $now): bool
    {
        if ($this->age(Checker::STATE_LAST_CHECK, $now) < self::DAY
            || $this->age(self::STATE_LAST_QUEUED, $now) < self::RETRY_AFTER
        ) {
            return false;
        }
        $this->state->set(self::STATE_LAST_QUEUED, gmdate('Y-m-d H:i:s', $now));

        return true;
    }

    /**
     * Seconds since a recorded time, or a very large number when there is none.
     */
    private function age(string $name, int $now): int
    {
        $value = $this->state->get($name);
        $time = $value !== null ? strtotime($value . ' UTC') : false;

        return $time === false ? PHP_INT_MAX : $now - $time;
    }
}
