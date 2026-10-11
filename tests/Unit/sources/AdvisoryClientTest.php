<?php

declare(strict_types=1);

namespace ruvelo\securityalerts\tests\Unit\sources;

use PHPUnit\Framework\TestCase;
use ruvelo\securityalerts\exceptions\SourceException;
use ruvelo\securityalerts\sources\AdvisoryClient;
use ruvelo\securityalerts\sources\FetcherInterface;
use ruvelo\securityalerts\tests\Fake\FakeFetcher;

class AdvisoryClientTest extends TestCase
{
    public function testAsksForPackageNamesOnly(): void
    {
        $fetcher = new FakeFetcher();

        $result = (new AdvisoryClient($fetcher))->fetch(['craftcms/cms', 'acme/craft-widgets']);

        $this->assertCount(1, $fetcher->requests);
        $this->assertSame(
            'POST https://packagist.org/api/security-advisories/ packages[]=craftcms%2Fcms&packages[]=acme%2Fcraft-widgets',
            $fetcher->requests[0],
        );
        $this->assertCount(3, $result['craftcms/cms']);
        $this->assertSame('CVE-2099-0005', $result['acme/craft-widgets'][0]['cve']);
    }

    public function testSplitsLongListsAndDeduplicates(): void
    {
        $fetcher = new FakeFetcher();
        $names = array_map(static fn(int $i): string => 'vendor/package-' . $i, range(1, 150));
        $names[] = 'vendor/package-1';

        (new AdvisoryClient($fetcher))->fetch($names);

        $this->assertCount(2, $fetcher->requests);
        $this->assertSame(100, substr_count($fetcher->requests[0], 'packages[]='));
        $this->assertSame(50, substr_count($fetcher->requests[1], 'packages[]='));
    }

    public function testAnUnexpectedAnswerIsAnError(): void
    {
        $fetcher = $this->createMock(FetcherInterface::class);
        $fetcher->method('postForm')->willReturn('<html>Maintenance</html>');

        $this->expectException(SourceException::class);
        (new AdvisoryClient($fetcher))->fetch(['a/b']);
    }
}
