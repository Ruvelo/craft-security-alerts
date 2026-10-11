<?php

declare(strict_types=1);

namespace ruvelo\securityalerts\tests\Unit\models;

use PHPUnit\Framework\TestCase;
use ruvelo\securityalerts\models\Finding;
use ruvelo\securityalerts\models\Findings;
use ruvelo\securityalerts\tests\Fake\Findings as Make;

class FindingTest extends TestCase
{
    public function testOnlyHttpLinksAreSafe(): void
    {
        $base = Make::make();
        $js = new Finding('a/b', '1.0.0', 'X', 't', 'javascript:alert(1)', null, null, null);
        $none = new Finding('a/b', '1.0.0', 'X', 't', null, null, null, null);

        $this->assertSame('https://example.com/PKSA-1', $base->safeLink());
        $this->assertNull($js->safeLink());
        $this->assertNull($none->safeLink());
    }

    public function testToArrayHasTheDocumentedKeys(): void
    {
        $this->assertSame(
            ['package', 'installed_version', 'advisory_id', 'title', 'link', 'cve', 'severity', 'severity_level', 'fixed_in', 'fixed_after', 'exploited'],
            array_keys(Make::make()->toArray()),
        );
    }

    public function testFixedLabelPrefersTheReleaseThenFallsBackToTheLastAffectedVersion(): void
    {
        $release = new Finding('a/b', '1.0.0', 'X', 't', null, null, null, '1.4.2', fixedAfter: '1.4.1');
        $after = new Finding('a/b', '1.0.0', 'X', 't', null, null, null, null, fixedAfter: '5.6.16');
        $none = new Finding('a/b', '1.0.0', 'X', 't', null, null, null, null);

        $this->assertSame('1.4.2', $release->fixedLabel());
        $this->assertSame('later than 5.6.16', $after->fixedLabel());
        $this->assertNull($none->fixedLabel());
        $this->assertSame('fixed in 1.4.2', $release->fixedPhrase());
        $this->assertSame('fixed in a release after 5.6.16', $after->fixedPhrase());
        $this->assertSame('no fixed version listed', $none->fixedPhrase());
    }

    public function testSortedPutsExploitedFirstThenSeverity(): void
    {
        $sorted = Findings::sorted([
            Make::make(advisory: 'PKSA-1', severity: 'low'),
            Make::make(advisory: 'PKSA-2', severity: 'critical'),
            Make::make(advisory: 'PKSA-3', severity: 'medium', exploited: true),
        ]);

        $this->assertSame(['PKSA-3', 'PKSA-2', 'PKSA-1'], array_map(static fn(Finding $f): string => $f->advisoryId, $sorted));
        $this->assertSame(1, Findings::exploitedCount($sorted));
    }
}
