<?php

declare(strict_types=1);

namespace ruvelo\securityalerts\tests\Unit\services;

use PHPUnit\Framework\TestCase;
use ruvelo\securityalerts\exceptions\SourceException;
use ruvelo\securityalerts\models\Finding;
use ruvelo\securityalerts\services\AdvisoryMatcher;
use ruvelo\securityalerts\services\ComposerLock;
use ruvelo\securityalerts\services\Scanner;
use ruvelo\securityalerts\sources\AdvisoryClient;
use ruvelo\securityalerts\sources\KevCatalogue;
use ruvelo\securityalerts\tests\Fake\FakeFetcher;

class ScannerTest extends TestCase
{
    private FakeFetcher $fetcher;

    protected function setUp(): void
    {
        $this->fetcher = new FakeFetcher();
    }

    /**
     * @param array<string, string>|SourceException $lock
     */
    private function scanner(array|SourceException $lock, ?string $craftVersion = '5.6.10'): Scanner
    {
        $composerLock = $this->createMock(ComposerLock::class);
        if ($lock instanceof SourceException) {
            $composerLock->method('packages')->willThrowException($lock);
        } else {
            $composerLock->method('packages')->willReturn($lock);
        }

        return new Scanner(
            $composerLock,
            new AdvisoryClient($this->fetcher),
            new KevCatalogue($this->fetcher),
            new AdvisoryMatcher(),
            $craftVersion,
        );
    }

    /**
     * @param list<Finding> $findings
     * @return list<string>
     */
    private function cves(array $findings): array
    {
        return array_map(static fn(Finding $f): string => (string)$f->cve, $findings);
    }

    public function testFlagsAnExploitedCoreFlawFirst(): void
    {
        $result = $this->scanner(['craftcms/cms' => '5.6.10', 'acme/craft-widgets' => '1.2.0'])->scan();

        $first = $result->findings[0];
        $this->assertSame('CVE-2025-32432', $first->cve);
        $this->assertTrue($first->exploited);
        $this->assertSame('5.6.10', $first->installedVersion);
        $this->assertSame('5.6.17', $first->fixedIn);
        $this->assertContains('CVE-2099-0002', $this->cves($result->findings));
        $this->assertSame([], $result->warnings);
        $this->assertSame(2, $result->packagesChecked);
    }

    public function testAnAdvisoryEndingAtALastAffectedVersionReportsTheFixAsLater(): void
    {
        $result = $this->scanner(['craftcms/cms' => '5.6.10'])->scan();

        $xss = array_values(array_filter($result->findings, static fn(Finding $f): bool => $f->cve === 'CVE-2099-0002'));
        $this->assertNull($xss[0]->fixedIn);
        $this->assertSame('5.7.9', $xss[0]->fixedAfter);
        $this->assertSame('later than 5.7.9', $xss[0]->fixedLabel());
    }

    public function testAPatchedSiteIsClean(): void
    {
        $result = $this->scanner(['craftcms/cms' => '5.8.1'])->scan();

        $this->assertSame([], $result->findings);
    }

    public function testExploitedComesBeforeSeverity(): void
    {
        // CVE-2099-0005 is listed as exploited in the fixture, and is rated only "high".
        $result = $this->scanner(['craftcms/cms' => '5.6.10', 'acme/craft-widgets' => '1.2.0'])->scan();

        $this->assertSame(
            ['CVE-2025-32432', 'CVE-2099-0005'],
            array_slice($this->cves($result->exploited()), 0, 2),
        );
        $this->assertSame(['CVE-2025-32432', 'CVE-2099-0005'], array_slice($this->cves($result->findings), 0, 2));
    }

    public function testPluginsAreMatchedByTheirInstalledVersion(): void
    {
        $result = $this->scanner(['craftcms/cms' => '5.8.1', 'craftcms/commerce' => '5.3.0', 'acme/craft-widgets' => '1.4.2'])->scan();

        $this->assertSame(['CVE-2099-0004'], $this->cves($result->findings));
        $this->assertNull($result->findings[0]->severity);
        $this->assertSame('5.3.1', $result->findings[0]->fixedIn);
    }

    public function testAdvisoryWithoutACveIsStillReported(): void
    {
        $result = $this->scanner(['craftcms/cms' => '5.8.1', 'acme/craft-widgets' => '2.0.1'])->scan();

        $this->assertCount(1, $result->findings);
        $this->assertNull($result->findings[0]->cve);
        $this->assertFalse($result->findings[0]->exploited);
        $this->assertSame('2.0.5', $result->findings[0]->fixedIn);
    }

    public function testPackagesNotInstalledAreIgnored(): void
    {
        $result = $this->scanner(['craftcms/cms' => '5.8.1'])->scan();

        $this->assertNotContains('CVE-2099-0007', $this->cves($result->findings));
    }

    public function testOnlyInstalledPackageNamesAreSent(): void
    {
        $this->scanner(['craftcms/cms' => '5.8.1', 'acme/craft-widgets' => '1.4.2'])->scan();

        $this->assertSame(
            'POST https://packagist.org/api/security-advisories/ packages[]=craftcms%2Fcms&packages[]=acme%2Fcraft-widgets',
            $this->fetcher->requests[0],
        );
    }

    public function testASilentCisaOutageWarnsAndFlagsNothing(): void
    {
        $this->fetcher->kevDown = true;

        $result = $this->scanner(['craftcms/cms' => '5.6.10'])->scan();

        $this->assertNotSame([], $result->findings);
        $this->assertSame([], $result->exploited());
        $this->assertStringContainsString('CISA', $result->warnings[0]);
    }

    public function testPackagistOutageIsAnError(): void
    {
        $this->fetcher->packagistDown = true;

        $this->expectException(SourceException::class);
        $this->scanner(['craftcms/cms' => '5.6.10'])->scan();
    }

    public function testMissingLockfileStillChecksCraftItself(): void
    {
        $result = $this->scanner(new SourceException('composer.lock was not found'), '5.6.10')->scan();

        $this->assertSame('CVE-2025-32432', $result->findings[0]->cve);
        $this->assertSame('composer.lock was not found', $result->warnings[0]);
        $this->assertSame(1, $result->packagesChecked);
    }

    public function testUnreadableCraftVersionStillChecksPlugins(): void
    {
        $result = $this->scanner(['acme/craft-widgets' => '1.2.0'], 'dev')->scan();

        $this->assertContains('CVE-2099-0005', $this->cves($result->findings));
        $this->assertStringContainsString('Craft version could not be read', $result->warnings[0]);
    }

    public function testNothingToCheckIsAnError(): void
    {
        $this->expectException(SourceException::class);
        $this->expectExceptionMessage('nothing to check');

        $this->scanner(new SourceException('no lock'), null)->scan();
    }
}
