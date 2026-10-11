<?php

declare(strict_types=1);

namespace ruvelo\securityalerts\tests\Unit\services;

use PHPUnit\Framework\TestCase;
use ruvelo\securityalerts\models\Finding;
use ruvelo\securityalerts\models\Settings;
use ruvelo\securityalerts\services\Notifier;
use ruvelo\securityalerts\tests\Fake\FakeMailer;
use ruvelo\securityalerts\tests\Fake\Findings;
use ruvelo\securityalerts\tests\Fake\InMemoryStore;

class NotifierTest extends TestCase
{
    private InMemoryStore $store;

    private FakeMailer $mailer;

    protected function setUp(): void
    {
        $this->store = new InMemoryStore();
        $this->mailer = new FakeMailer();
    }

    private function notifier(?Settings $settings = null): Notifier
    {
        $settings ??= new Settings(['emails' => 'ops@example.com']);

        return new Notifier($settings, $this->store, $this->mailer, 'Example Site', 'https://example.com/admin/utilities/security-alerts');
    }

    /**
     * @param list<Finding> $findings
     */
    private function store(array $findings): void
    {
        foreach ($findings as $f) {
            $this->store->insert($f);
        }
    }

    public function testExploitedComesFirstAndIsLabelled(): void
    {
        $this->store([
            Findings::make(advisory: 'PKSA-1', title: 'Quiet one'),
            Findings::make(advisory: 'PKSA-2', title: 'Loud one', exploited: true),
        ]);

        $sent = $this->notifier()->notifyPending();

        $this->assertSame(2, $sent);
        $this->assertCount(1, $this->mailer->sent);
        $message = $this->mailer->sent[0];
        $this->assertSame(['ops@example.com'], $message->parts['to']);
        $this->assertSame('Exploited — patch now: 1 known vulnerability is being exploited on Example Site', $message->parts['subject']);
        $html = (string)$message->parts['html'];
        $this->assertStringContainsString('Exploited — patch now', $html);
        $this->assertLessThan(strpos($html, 'Quiet one'), strpos($html, 'Loud one'));
        $this->assertStringContainsString('security-alerts', $html);
        $this->assertStringContainsString('EXPLOITED — PATCH NOW', (string)$message->parts['text']);
    }

    public function testNothingIsSentTwice(): void
    {
        $this->store([Findings::make()]);
        $notifier = $this->notifier();

        $notifier->notifyPending();
        $second = $notifier->notifyPending();

        $this->assertSame(0, $second);
        $this->assertCount(1, $this->mailer->sent);
    }

    public function testAFindingThatBecomesExploitedIsSentAgain(): void
    {
        $this->store([Findings::make(advisory: 'PKSA-1')]);
        $notifier = $this->notifier();
        $notifier->notifyPending();

        $this->store->update(Findings::make(advisory: 'PKSA-1', exploited: true));
        $sent = $notifier->notifyPending();

        $this->assertSame(1, $sent);
        $this->assertCount(2, $this->mailer->sent);
        $this->assertStringStartsWith('Exploited', $this->mailer->sent[1]->getSubject());
    }

    public function testBelowTheMinimumSeverityIsNotSentButIsNotRetried(): void
    {
        $this->store([Findings::make(severity: 'low')]);
        $notifier = $this->notifier(new Settings(['emails' => 'ops@example.com', 'minimumSeverity' => 'high']));

        $this->assertSame(0, $notifier->notifyPending());
        $this->assertSame([], $this->store->pendingNotification());
        $this->assertSame([], $this->mailer->sent);
    }

    public function testExploitedIgnoresTheMinimumSeverity(): void
    {
        $this->store([Findings::make(severity: 'low', exploited: true)]);
        $notifier = $this->notifier(new Settings(['emails' => 'ops@example.com', 'minimumSeverity' => 'critical']));

        $this->assertSame(1, $notifier->notifyPending());
    }

    public function testUnratedCountsAsHighForTheMinimum(): void
    {
        $this->store([Findings::make(severity: null)]);
        $notifier = $this->notifier(new Settings(['emails' => 'ops@example.com', 'minimumSeverity' => 'high']));

        $this->assertSame(1, $notifier->notifyPending());
        $this->assertStringContainsString('(not rated)', (string)$this->mailer->sent[0]->parts['text']);
    }

    public function testDisabledOrWithoutRecipientsKeepsFindingsPending(): void
    {
        $this->store([Findings::make()]);

        $this->assertSame(0, $this->notifier(new Settings(['emails' => '']))->notifyPending());
        $this->assertSame(0, $this->notifier(new Settings(['emails' => 'ops@example.com', 'enabled' => false]))->notifyPending());

        $this->assertCount(1, $this->store->pendingNotification());
        $this->assertSame(1, $this->notifier()->notifyPending());
    }

    public function testAFailedSendKeepsFindingsPending(): void
    {
        $this->store([Findings::make()]);
        $this->mailer->failing = true;

        $this->assertSame(0, $this->notifier()->notifyPending());
        $this->assertCount(1, $this->store->pendingNotification());
    }

    public function testAdvisoryTextIsEscapedAndOnlyHttpLinksAreLinked(): void
    {
        $evil = new Finding('acme/x', '1.0.0', 'PKSA-9', '<script>alert(1)</script>', 'javascript:alert(1)', null, 'high', null);
        $good = new Finding('acme/y', '1.0.0', 'PKSA-8', 'Fine', 'https://example.com/a?b=1&c=2', null, 'high', null);
        $this->store([$evil, $good]);

        $this->notifier()->notifyPending();

        $html = (string)$this->mailer->sent[0]->parts['html'];
        $this->assertStringNotContainsString('<script>', $html);
        $this->assertStringContainsString('&lt;script&gt;', $html);
        $this->assertStringNotContainsString('javascript:', $html);
        $this->assertStringContainsString('href="https://example.com/a?b=1&amp;c=2"', $html);
    }

    public function testSubjectWithoutExploitedItems(): void
    {
        $this->assertSame('3 new security advisories for Example Site', $this->notifier()->subject(0, 3));
        $this->assertSame('1 new security advisory for Example Site', $this->notifier()->subject(0, 1));
        $this->assertSame(
            'Exploited — patch now: 2 known vulnerabilities are being exploited on Example Site',
            $this->notifier()->subject(2, 5),
        );
    }
}
