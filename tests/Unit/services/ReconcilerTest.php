<?php

declare(strict_types=1);

namespace ruvelo\securityalerts\tests\Unit\services;

use LogicException;
use PHPUnit\Framework\TestCase;
use ruvelo\securityalerts\models\ScanResult;
use ruvelo\securityalerts\services\Reconciler;
use ruvelo\securityalerts\tests\Fake\Findings;
use ruvelo\securityalerts\tests\Fake\InMemoryStore;

class ReconcilerTest extends TestCase
{
    private InMemoryStore $store;

    private Reconciler $reconciler;

    protected function setUp(): void
    {
        $this->store = new InMemoryStore();
        $this->reconciler = new Reconciler($this->store);
    }

    public function testFirstRunReportsEverythingAsNew(): void
    {
        $changes = $this->reconciler->reconcile(Findings::result([Findings::make(advisory: 'PKSA-1'), Findings::make(advisory: 'PKSA-2')]));

        $this->assertCount(2, $changes->new);
        $this->assertSame([], $changes->becameExploited);
        $this->assertCount(2, $this->store->all());
    }

    public function testSecondRunWithTheSameFindingsIsNotNews(): void
    {
        $result = Findings::result([Findings::make(advisory: 'PKSA-1')]);
        $this->reconciler->reconcile($result);

        $changes = $this->reconciler->reconcile($result);

        $this->assertSame([], $changes->new);
        $this->assertSame([], $changes->becameExploited);
        $this->assertSame(0, $changes->resolved);
        $this->assertCount(1, $this->store->all());
    }

    public function testAFindingThatBecomesExploitedIsNewsAgain(): void
    {
        $this->reconciler->reconcile(Findings::result([Findings::make(advisory: 'PKSA-1')]));

        $changes = $this->reconciler->reconcile(Findings::result([Findings::make(advisory: 'PKSA-1', exploited: true)]));

        $this->assertSame([], $changes->new);
        $this->assertCount(1, $changes->becameExploited);
        $this->assertTrue($this->store->all()[0]->exploited);
    }

    public function testExploitedStaysExploitedWhenTheCatalogueIsUnavailable(): void
    {
        $this->reconciler->reconcile(Findings::result([Findings::make(advisory: 'PKSA-1', exploited: true)]));

        $changes = $this->reconciler->reconcile(Findings::result([Findings::make(advisory: 'PKSA-1', exploited: false)], ['CISA is down.']));

        $this->assertSame([], $changes->becameExploited);
        $this->assertTrue($this->store->all()[0]->exploited);
    }

    public function testFindingsThatNoLongerApplyAreRemoved(): void
    {
        $this->reconciler->reconcile(Findings::result([Findings::make(advisory: 'PKSA-1'), Findings::make(advisory: 'PKSA-2')]));

        $changes = $this->reconciler->reconcile(Findings::result([Findings::make(advisory: 'PKSA-2')]));

        $this->assertSame(1, $changes->resolved);
        $this->assertCount(1, $this->store->all());
        $this->assertSame('PKSA-2', $this->store->all()[0]->advisoryId);
    }

    public function testAnIncompleteCheckResolvesNothing(): void
    {
        $this->reconciler->reconcile(Findings::result([Findings::make(advisory: 'PKSA-1'), Findings::make(advisory: 'PKSA-2')]));

        $changes = $this->reconciler->reconcile(Findings::result([Findings::make(advisory: 'PKSA-2')], ['A source could not be read.']));

        $this->assertSame(0, $changes->resolved);
        $this->assertCount(2, $this->store->all());
    }

    public function testAFindingThatReturnsAfterBeingFixedIsNewAgain(): void
    {
        $this->reconciler->reconcile(Findings::result([Findings::make(advisory: 'PKSA-1')]));
        $this->reconciler->reconcile(Findings::result([]));

        $changes = $this->reconciler->reconcile(Findings::result([Findings::make(advisory: 'PKSA-1')]));

        $this->assertCount(1, $changes->new);
    }

    public function testTheInstalledVersionIsRefreshed(): void
    {
        $this->reconciler->reconcile(Findings::result([Findings::make(advisory: 'PKSA-1', installed: '1.2.0')]));

        $this->reconciler->reconcile(Findings::result([Findings::make(advisory: 'PKSA-1', installed: '1.3.0')]));

        $this->assertSame('1.3.0', $this->store->all()[0]->installedVersion);
    }

    public function testTheSameVulnerabilityUnderAnotherIdIsTheSameFinding(): void
    {
        $this->store->seed(Findings::make(advisory: 'PKSA-1'));

        // Another source names it GHSA-1 and lists PKSA-1 as an alias.
        $result = Findings::result([Findings::make(advisory: 'GHSA-1')], aliases: ['PKSA-1']);
        $changes = $this->reconciler->reconcile($result);

        $this->assertSame([], $changes->new);
        $this->assertSame(0, $changes->resolved);
        $this->assertCount(1, $this->store->all());
        $this->assertSame('PKSA-1', $this->store->all()[0]->advisoryId, 'The row keeps the id it was first stored under');
        $this->assertSame(['PKSA-1'], $this->store->all()[0]->aliases, 'and remembers what else it is called');
    }

    public function testTheSameVulnerabilityIsRecognisedByItsCveWhenNoAliasIsGiven(): void
    {
        $stored = Findings::make(advisory: 'PKSA-1');
        $this->store->seed($stored);
        $renamed = new \ruvelo\securityalerts\models\Finding($stored->package, $stored->installedVersion, 'GHSA-xyz', $stored->title, $stored->link, $stored->cve, 'high', '9.9.9', false);

        $changes = $this->reconciler->reconcile(Findings::result([$renamed]));

        $this->assertSame([], $changes->new);
        $this->assertSame(0, $changes->resolved);
        $this->assertCount(1, $this->store->all());
    }

    public function testAResultThatDidNotComeFromAScanCannotBeReconciled(): void
    {
        $this->expectException(LogicException::class);

        $this->reconciler->reconcile(new ScanResult([], [], 0));
    }
}
