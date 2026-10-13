<?php

declare(strict_types=1);

namespace ruvelo\securityalerts\tests\Unit\services;

use PHPUnit\Framework\TestCase;
use ruvelo\securityalerts\models\Finding;
use ruvelo\securityalerts\models\Settings;
use ruvelo\securityalerts\services\Checker;
use ruvelo\securityalerts\services\Notifier;
use ruvelo\securityalerts\services\Reconciler;
use ruvelo\securityalerts\tests\Fake\FakeClient;
use ruvelo\securityalerts\tests\Fake\FakeMailer;
use ruvelo\securityalerts\tests\Fake\InMemoryState;
use ruvelo\securityalerts\tests\Fake\InMemoryStore;
use ruvelo\securityalerts\tests\Fake\Wiring;

/**
 * A site that ran 1.0 has a table full of findings it already emailed about. The first check after
 * upgrading to 1.1 must recognise them, whichever source answers, and send nothing again.
 */
class UpgradeFromOneZeroTest extends TestCase
{
    private InMemoryStore $store;

    private FakeMailer $mailer;

    protected function setUp(): void
    {
        $this->store = new InMemoryStore();
        $this->mailer = new FakeMailer();
    }

    /**
     * The rows 1.0 left: what Packagist said, with no aliases (1.0 had no such column), all emailed.
     *
     * @return list<Finding>
     */
    private function seedOneZeroRows(): array
    {
        $first = Wiring::scanner(new FakeClient())->scan();
        $this->assertCount(4, $first->findings);
        foreach ($first->findings as $finding) {
            $this->store->seed(new Finding(
                $finding->package,
                $finding->installedVersion,
                $finding->advisoryId,
                $finding->title,
                $finding->link,
                $finding->cve,
                $finding->severity,
                $finding->fixedIn,
                $finding->exploited,
                fixedAfter: $finding->fixedAfter,
            ));
        }

        return $first->findings;
    }

    private function check(FakeClient $client, string $source): void
    {
        $checker = new Checker(
            Wiring::scanner($client, $source),
            new Reconciler($this->store),
            new Notifier(new Settings(['emails' => 'ops@example.com']), $this->store, $this->mailer, 'Example Site'),
            new InMemoryState(),
        );
        $before = $this->store->all();

        $outcome = $checker->run();

        $this->assertSame([], $outcome->result->warnings);
        $this->assertCount(4, $outcome->result->findings);
        $this->assertSame([], $outcome->changes->new, 'nothing is new');
        $this->assertSame([], $outcome->changes->becameExploited);
        $this->assertSame(0, $outcome->changes->resolved);
        $this->assertSame(0, $outcome->emailed);
        $this->assertSame([], $this->mailer->sent, 'nothing is emailed');
        $this->assertCount(count($before), $this->store->all(), 'no row is added or removed');
        $this->assertSame(
            array_map(static fn(Finding $f): string => $f->key(), $before),
            array_map(static fn(Finding $f): string => $f->key(), $this->store->all()),
            'every row keeps its identity',
        );
    }

    public function testRowsFromOneZeroAreKnownToThePublicPath(): void
    {
        $this->seedOneZeroRows();

        $this->check(new FakeClient(), 'public');
    }

    public function testRowsFromOneZeroAreKnownToTheValtryPath(): void
    {
        $this->seedOneZeroRows();
        $client = new FakeClient();
        $client->valtryUp = true;

        $this->check($client, 'valtry');

        $this->assertSame('valtry', Wiring::scanner($client, 'valtry')->scan()->source());
    }

    public function testRowsFromOneZeroAreKnownWhenValtryNamesTheAdvisoriesDifferently(): void
    {
        $this->seedOneZeroRows();
        $client = new FakeClient();
        $client->valtryUp = true;
        $client->valtryRenamesIds = true;

        $this->check($client, 'valtry');

        $ids = array_map(static fn(Finding $f): string => $f->advisoryId, $this->store->all());
        $this->assertSame([], array_filter($ids, static fn(string $id): bool => str_starts_with($id, 'VAL-')), 'rows keep the ids 1.0 stored');
    }

    public function testAnExploitedRowThatWasEmailedStaysQuietOnBothPaths(): void
    {
        $rows = $this->seedOneZeroRows();
        $this->assertTrue($rows[0]->exploited);

        $this->check(new FakeClient(), 'public');
        $client = new FakeClient();
        $client->valtryUp = true;
        $this->check($client, 'valtry');
    }
}
