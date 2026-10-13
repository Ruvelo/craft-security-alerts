<?php

declare(strict_types=1);

namespace ruvelo\securityalerts\tests\Unit\models;

use PHPUnit\Framework\TestCase;
use ruvelo\securityalerts\models\Settings;

class SettingsTest extends TestCase
{
    public function testDefaults(): void
    {
        $settings = new Settings();

        $this->assertTrue($settings->enabled);
        $this->assertSame([], $settings->recipients());
        $this->assertSame('medium', $settings->minimumSeverity);
        $this->assertFalse($settings->checkOnCpUse, 'the fallback is opt-in');
        $this->assertTrue($settings->validate());
    }

    public function testRecipientsAreSplitValidatedAndDeduplicated(): void
    {
        $settings = new Settings(['emails' => "a@example.com, b@example.com;\nnot-an-email  a@example.com"]);

        $this->assertSame(['a@example.com', 'b@example.com'], $settings->recipients());
    }

    public function testInvalidAddressesFailValidationAndNameThemselves(): void
    {
        $settings = new Settings(['emails' => 'a@example.com, nope']);

        $this->assertFalse($settings->validate());
        $this->assertStringContainsString('nope', $settings->getFirstError('emails') ?? '');
    }

    public function testMinimumSeverity(): void
    {
        $this->assertTrue((new Settings(['minimumSeverity' => 'critical']))->validate());
        $this->assertSame('critical', (new Settings(['minimumSeverity' => 'critical']))->minimum()->value);

        $bad = new Settings(['minimumSeverity' => 'catastrophic']);
        $this->assertFalse($bad->validate());
        $this->assertSame('medium', $bad->minimum()->value, 'an unknown value falls back to medium');
    }

    public function testTheAdvisorySourceDefaultsToValtryAndAcceptsPublicOnly(): void
    {
        $this->assertSame('valtry', (new Settings())->advisorySource);
        $this->assertTrue((new Settings(['advisorySource' => 'public']))->validate());
        $this->assertFalse((new Settings(['advisorySource' => 'elsewhere']))->validate());
        $this->assertSame(['valtry', 'public'], array_keys(Settings::sourceOptions()));
    }

    public function testSeverityOptionsListEveryLevel(): void
    {
        $this->assertSame(['low', 'medium', 'high', 'critical'], array_keys(Settings::severityOptions()));
    }

    public function testEnvironmentVariablesAreResolved(): void
    {
        putenv('SECURITY_ALERTS_TEST_EMAILS=ops@example.com');
        try {
            $this->assertSame(['ops@example.com'], (new Settings(['emails' => '$SECURITY_ALERTS_TEST_EMAILS']))->recipients());
        } finally {
            putenv('SECURITY_ALERTS_TEST_EMAILS');
        }
    }
}
