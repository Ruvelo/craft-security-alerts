<?php

declare(strict_types=1);

namespace ruvelo\securityalerts\tests\Unit\services;

use PHPUnit\Framework\TestCase;
use ruvelo\securityalerts\events\FindingsEvent;
use ruvelo\securityalerts\exceptions\SourceException;
use ruvelo\securityalerts\models\Settings;
use ruvelo\securityalerts\services\AdvisoryMatcher;
use ruvelo\securityalerts\services\Checker;
use ruvelo\securityalerts\services\ComposerLock;
use ruvelo\securityalerts\services\Notifier;
use ruvelo\securityalerts\services\Reconciler;
use ruvelo\securityalerts\services\Scanner;
use ruvelo\securityalerts\sources\AdvisoryClient;
use ruvelo\securityalerts\sources\KevCatalogue;
use ruvelo\securityalerts\tests\Fake\FakeFetcher;
use ruvelo\securityalerts\tests\Fake\FakeMailer;
use ruvelo\securityalerts\tests\Fake\InMemoryState;
use ruvelo\securityalerts\tests\Fake\InMemoryStore;
use yii\base\Event;

class CheckerTest extends TestCase
{
    private InMemoryStore $store;

    private InMemoryState $state;

    private FakeMailer $mailer;

    private FakeFetcher $fetcher;

    protected function setUp(): void
    {
        $this->store = new InMemoryStore();
        $this->state = new InMemoryState();
        $this->mailer = new FakeMailer();
        $this->fetcher = new FakeFetcher();
    }

    protected function tearDown(): void
    {
        Event::offAll();
    }

    private function checker(string $craftVersion): Checker
    {
        $lock = $this->createMock(ComposerLock::class);
        $lock->method('packages')->willReturn(['craftcms/cms' => $craftVersion, 'acme/craft-widgets' => '1.2.0']);

        return new Checker(
            new Scanner($lock, new AdvisoryClient($this->fetcher), new KevCatalogue($this->fetcher), new AdvisoryMatcher(), $craftVersion),
            new Reconciler($this->store),
            new Notifier(new Settings(['emails' => 'ops@example.com']), $this->store, $this->mailer, 'Example Site'),
            $this->state,
        );
    }

    public function testStoresTriggersTheEventNotifiesAndRemembersWhenItRan(): void
    {
        $events = [];
        Event::on(Checker::class, Checker::EVENT_FINDINGS_FOUND, static function(FindingsEvent $e) use (&$events): void {
            $events[] = $e;
        });

        $outcome = $this->checker('5.6.10')->run();

        $this->assertNotSame([], $outcome->result->findings);
        $this->assertCount(count($outcome->result->findings), $this->store->all());
        $this->assertCount(1, $events);
        $this->assertSame($outcome->result->findings, $events[0]->findings);
        $this->assertSame(count($outcome->changes->new), count($events[0]->newFindings));
        $this->assertSame($outcome->result, $events[0]->result);
        $this->assertSame($outcome->emailed, count($outcome->result->findings));
        $this->assertCount(1, $this->mailer->sent);
        $this->assertNotNull($this->state->get(Checker::STATE_LAST_CHECK));
    }

    public function testASecondRunIsQuietButStillTriggersTheEvent(): void
    {
        $events = 0;
        Event::on(Checker::class, Checker::EVENT_FINDINGS_FOUND, static function() use (&$events): void {
            $events++;
        });
        $checker = $this->checker('5.6.10');
        $checker->run();

        $second = $checker->run();

        $this->assertSame(0, $second->emailed);
        $this->assertSame([], $second->changes->new);
        $this->assertCount(1, $this->mailer->sent);
        $this->assertSame(2, $events);
    }

    public function testNoEventWhenNothingApplies(): void
    {
        $events = 0;
        Event::on(Checker::class, Checker::EVENT_FINDINGS_FOUND, static function() use (&$events): void {
            $events++;
        });
        $lock = $this->createMock(ComposerLock::class);
        $lock->method('packages')->willReturn(['craftcms/cms' => '5.8.1']);
        $checker = new Checker(
            new Scanner($lock, new AdvisoryClient($this->fetcher), new KevCatalogue($this->fetcher), new AdvisoryMatcher()),
            new Reconciler($this->store),
            new Notifier(new Settings(), $this->store, $this->mailer, 'Example Site'),
            $this->state,
        );

        $checker->run();

        $this->assertSame(0, $events);
        $this->assertNotNull($this->state->get(Checker::STATE_LAST_CHECK));
    }

    public function testAFailedScanChangesNothing(): void
    {
        $this->fetcher->packagistDown = true;

        try {
            $this->checker('5.6.10')->run();
            $this->fail('Expected a SourceException');
        } catch (SourceException) {
            $this->assertSame([], $this->store->all());
            $this->assertNull($this->state->get(Checker::STATE_LAST_CHECK));
            $this->assertSame([], $this->mailer->sent);
        }
    }
}
