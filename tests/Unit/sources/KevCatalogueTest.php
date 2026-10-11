<?php

declare(strict_types=1);

namespace ruvelo\securityalerts\tests\Unit\sources;

use PHPUnit\Framework\TestCase;
use ruvelo\securityalerts\exceptions\SourceException;
use ruvelo\securityalerts\sources\FetcherInterface;
use ruvelo\securityalerts\sources\KevCatalogue;
use ruvelo\securityalerts\tests\Fake\FakeFetcher;

class KevCatalogueTest extends TestCase
{
    public function testReadsTheCveIdsInUpperCase(): void
    {
        $fetcher = new FakeFetcher();

        $cves = (new KevCatalogue($fetcher))->exploitedCves();

        $this->assertSame(['GET ' . KevCatalogue::URL], $fetcher->requests);
        $this->assertArrayHasKey('CVE-2025-32432', $cves);
        $this->assertArrayHasKey('CVE-2099-0005', $cves);
        $this->assertArrayNotHasKey('CVE-2099-0001', $cves);
    }

    public function testRejectsAnythingElse(): void
    {
        $fetcher = $this->createMock(FetcherInterface::class);
        $fetcher->method('get')->willReturn('{"vulnerabilities": "none"}');

        $this->expectException(SourceException::class);
        (new KevCatalogue($fetcher))->exploitedCves();
    }
}
