<?php

declare(strict_types=1);

namespace ruvelo\securityalerts\tests\Unit\services;

use PHPUnit\Framework\TestCase;
use ruvelo\securityalerts\exceptions\SourceException;
use ruvelo\securityalerts\models\Finding;
use ruvelo\securityalerts\services\Scanner;
use ruvelo\securityalerts\tests\Fake\FakeClient;
use ruvelo\securityalerts\tests\Fake\Wiring;

/**
 * The scanner on the public feeds, with the real core behind it and a fake HTTP client in front.
 */
class ScannerTest extends TestCase
{
    private FakeClient $client;

    /** @var list<string> */
    private array $locks = [];

    protected function setUp(): void
    {
        $this->client = new FakeClient();
    }

    protected function tearDown(): void
    {
        foreach ($this->locks as $lock) {
            @unlink($lock);
        }
        putenv('RUVELO_ADVISORIES_SOURCE');
    }

    /**
     * @param array<string, string> $packages
     */
    private function scanner(array $packages, ?string $craftVersion = '5.6.10', string $source = 'public'): Scanner
    {
        $this->locks[] = $lock = Wiring::lock($packages);

        return Wiring::scanner($this->client, $source, $lock, $craftVersion);
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
        $this->assertSame('public', $result->source());
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

        $this->assertSame(['CVE-2025-32432', 'CVE-2099-0005'], array_slice($this->cves($result->exploited()), 0, 2));
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

        $this->assertStringContainsString('packages[]=acme%2Fcraft-widgets&packages[]=craftcms%2Fcms', $this->client->to('packagist.org')[0]);
        $this->assertCount(1, $this->client->to('packagist.org'));
        $this->assertStringNotContainsString('5.8.1', $this->client->to('packagist.org')[0]);
    }

    public function testDevPackagesAndDevBranchesAreNotSent(): void
    {
        $this->client = new FakeClient();
        Wiring::scanner($this->client)->scan();

        $sent = $this->client->to('packagist.org')[0];
        $this->assertStringContainsString('craftcms%2Fcms', $sent);
        $this->assertStringNotContainsString('phpunit', $sent, 'packages-dev is not sent');
        $this->assertStringNotContainsString('private-thing', $sent, 'dev-main is not sent');
        $this->assertStringNotContainsString('branch-thing', $sent, '2.x-dev is not sent');
    }

    public function testASilentCisaOutageWarnsAndFlagsNothing(): void
    {
        $this->client->kevDown = true;

        $result = $this->scanner(['craftcms/cms' => '5.6.10'])->scan();

        $this->assertNotSame([], $result->findings);
        $this->assertSame([], $result->exploited());
        $this->assertStringContainsString('CISA', $result->warnings[0]);
    }

    public function testPackagistOutageIsAnError(): void
    {
        $this->client->packagistDown = true;

        $this->expectException(SourceException::class);
        $this->scanner(['craftcms/cms' => '5.6.10'])->scan();
    }

    public function testMissingLockfileStillChecksCraftItself(): void
    {
        $result = Wiring::scanner($this->client, 'public', '/nonexistent/composer.lock', '5.6.10')->scan();

        $this->assertSame('CVE-2025-32432', $result->findings[0]->cve);
        $this->assertStringContainsString('composer.lock was not found', $result->warnings[0]);
        $this->assertSame(1, $result->packagesChecked);
    }

    public function testAnUnreadableLockfileStillChecksCraftItself(): void
    {
        $lock = (string)tempnam(sys_get_temp_dir(), 'sa-lock');
        $this->locks[] = $lock;
        file_put_contents($lock, 'not json');

        $result = Wiring::scanner($this->client, 'public', $lock, '5.6.10')->scan();

        $this->assertSame('CVE-2025-32432', $result->findings[0]->cve);
        $this->assertStringContainsString('valid JSON', $result->warnings[0]);
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
        $this->expectExceptionMessage('composer.lock was not found');

        Wiring::scanner($this->client, 'public', '/nonexistent/composer.lock', null)->scan();
    }

    public function testTheCraftVersionIsUsedWhenTheLockDoesNotListIt(): void
    {
        $result = $this->scanner(['acme/craft-widgets' => '1.2.0'], '5.6.10')->scan();

        $this->assertContains('CVE-2025-32432', $this->cves($result->findings));
        $this->assertSame(2, $result->packagesChecked);
    }

    // --- Valtry, the default source ---

    public function testValtryIsAskedFirstWithNamesOnlyAndAnswersTheSameFindings(): void
    {
        $this->client->valtryUp = true;
        $public = $this->scanner(['craftcms/cms' => '5.6.10', 'acme/craft-widgets' => '1.2.0'])->scan();
        $public = array_map(static fn(Finding $f): array => $f->toArray(), $public->findings);
        $this->client = $client = new FakeClient();
        $client->valtryUp = true;

        $result = $this->scanner(['craftcms/cms' => '5.6.10', 'acme/craft-widgets' => '1.2.0'], source: 'valtry')->scan();

        $this->assertSame('valtry', $result->source());
        $this->assertSame($public, array_map(static fn(Finding $f): array => $f->toArray(), $result->findings));
        $this->assertSame([], $client->to('packagist.org'));
        $this->assertSame([], $client->to('cisa.gov'), 'Valtry carries the exploited verdict');
        $sent = $client->to('valtry.test');
        $this->assertCount(1, $sent);
        $this->assertStringContainsString('craftcms/cms', $sent[0]);
        $this->assertStringNotContainsString('5.6.10', $sent[0], 'never versions');
        $this->assertStringNotContainsString('1.2.0', $sent[0]);
    }

    public function testAnUnreachableValtryFallsBackToTheFeeds(): void
    {
        $this->client->valtryUp = false;

        $result = $this->scanner(['craftcms/cms' => '5.6.10'], source: 'valtry')->scan();

        $this->assertSame('public', $result->source());
        $this->assertSame('CVE-2025-32432', $result->findings[0]->cve);
        $this->assertTrue($result->findings[0]->exploited);
        $this->assertCount(1, $this->client->to('packagist.org'));
    }

    public function testAnErrorFromValtryFallsBackToTheFeeds(): void
    {
        $this->client->valtryUp = true;
        $this->client->valtryStatus = 503;

        $result = $this->scanner(['craftcms/cms' => '5.6.10'], source: 'valtry')->scan();

        $this->assertSame('public', $result->source());
        $this->assertNotSame([], $result->findings);
    }

    public function testAnAnswerThatDoesNotVerifyFallsBackToTheFeeds(): void
    {
        $this->client->valtryUp = true;
        $this->client->tamper = static fn(string $body): string => str_replace('Craft CMS remote code execution vulnerability', 'Nothing to see', $body);

        $result = $this->scanner(['craftcms/cms' => '5.6.10'], source: 'valtry')->scan();

        $this->assertSame('public', $result->source());
        $this->assertStringContainsString('remote code execution', $result->findings[0]->title);
    }

    public function testThePublicSettingNeverContactsValtry(): void
    {
        $this->client->valtryUp = true;

        $result = $this->scanner(['craftcms/cms' => '5.6.10'], source: 'public')->scan();

        $this->assertSame('public', $result->source());
        $this->assertSame([], $this->client->to('valtry.test'));
    }

    public function testTheEnvironmentOptOutWinsOverTheSetting(): void
    {
        putenv('RUVELO_ADVISORIES_SOURCE=public');
        $this->client->valtryUp = true;

        $result = $this->scanner(['craftcms/cms' => '5.6.10'], source: 'valtry')->scan();

        $this->assertSame('public', $result->source());
        $this->assertSame([], $this->client->to('valtry.test'));
    }

    public function testTheSourceIsNamedNeutrally(): void
    {
        $this->client->valtryUp = true;

        $this->assertSame('Valtry Advisory API (signed answers)', $this->scanner(['craftcms/cms' => '5.6.10'], source: 'valtry')->scan()->sourceLabel());
        $this->assertSame('public feeds (Packagist and CISA)', $this->scanner(['craftcms/cms' => '5.6.10'])->scan()->sourceLabel());
    }
}
