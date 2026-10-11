<?php

declare(strict_types=1);

namespace ruvelo\securityalerts\tests\Unit\services;

use PHPUnit\Framework\TestCase;
use ruvelo\securityalerts\services\Checker;
use ruvelo\securityalerts\services\DailyTrigger;
use ruvelo\securityalerts\tests\Fake\InMemoryState;

class DailyTriggerTest extends TestCase
{
    private const NOW = 1_791_000_000;

    private InMemoryState $state;

    private DailyTrigger $trigger;

    protected function setUp(): void
    {
        $this->state = new InMemoryState();
        $this->trigger = new DailyTrigger($this->state);
    }

    public function testNeverCheckedQueuesOnce(): void
    {
        $this->assertTrue($this->trigger->claim(self::NOW));
        $this->assertFalse($this->trigger->claim(self::NOW + 5), 'a second visit must not queue another job');
    }

    public function testACheckInTheLastDayIsEnough(): void
    {
        $this->state->set(Checker::STATE_LAST_CHECK, gmdate('Y-m-d H:i:s', self::NOW - 23 * 3600));

        $this->assertFalse($this->trigger->claim(self::NOW));
    }

    public function testACheckOlderThanADayQueues(): void
    {
        $this->state->set(Checker::STATE_LAST_CHECK, gmdate('Y-m-d H:i:s', self::NOW - 25 * 3600));

        $this->assertTrue($this->trigger->claim(self::NOW));
    }

    public function testAJobThatNeverRanIsRetriedAfterAnHour(): void
    {
        $this->state->set(Checker::STATE_LAST_CHECK, gmdate('Y-m-d H:i:s', self::NOW - 48 * 3600));
        $this->assertTrue($this->trigger->claim(self::NOW));

        $this->assertFalse($this->trigger->claim(self::NOW + 1800));
        $this->assertTrue($this->trigger->claim(self::NOW + 3601));
    }
}
