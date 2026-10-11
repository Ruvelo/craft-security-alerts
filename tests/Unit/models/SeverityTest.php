<?php

declare(strict_types=1);

namespace ruvelo\securityalerts\tests\Unit\models;

use PHPUnit\Framework\TestCase;
use ruvelo\securityalerts\models\Severity;

class SeverityTest extends TestCase
{
    public function testUnratedAndUnknownCountAsHigh(): void
    {
        $this->assertSame(Severity::High, Severity::fromAdvisory(null));
        $this->assertSame(Severity::High, Severity::fromAdvisory('nonsense'));
    }

    public function testIsCaseInsensitiveAndRanked(): void
    {
        $this->assertSame(Severity::Critical, Severity::fromAdvisory(' CRITICAL '));
        $this->assertLessThan(Severity::Medium->rank(), Severity::Low->rank());
        $this->assertLessThan(Severity::Critical->rank(), Severity::High->rank());
        $this->assertSame('Medium', Severity::Medium->label());
    }
}
