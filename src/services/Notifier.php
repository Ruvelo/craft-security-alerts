<?php

declare(strict_types=1);

namespace ruvelo\securityalerts\services;

use Craft;
use ruvelo\securityalerts\models\Finding;
use ruvelo\securityalerts\models\Findings;
use ruvelo\securityalerts\models\Settings;
use Throwable;
use yii\helpers\Html;
use yii\mail\MailerInterface;

/**
 * Emails what is new: findings seen for the first time, and findings that became exploited.
 */
class Notifier
{
    public function __construct(
        private readonly Settings $settings,
        private readonly FindingStoreInterface $store,
        private readonly MailerInterface $mailer,
        private readonly string $siteName,
        private readonly ?string $utilityUrl = null,
    ) {
    }

    /**
     * @return int How many findings were put in an email
     */
    public function notifyPending(): int
    {
        $recipients = $this->settings->recipients();
        if (!$this->settings->enabled || $recipients === []) {
            // Nothing is marked, so turning email on later still reports what is open.
            return 0;
        }

        $pending = Findings::sorted($this->store->pendingNotification());
        if ($pending === []) {
            return 0;
        }

        // Exploited findings are always sent. The minimum severity filters the rest, and a
        // finding below it is marked as handled so that it is not reconsidered every day.
        $minimum = $this->settings->minimum()->rank();
        $toSend = array_values(array_filter(
            $pending,
            static fn(Finding $f): bool => $f->exploited || $f->severityLevel()->rank() >= $minimum,
        ));

        if ($toSend !== []) {
            try {
                $this->send($toSend, $recipients);
            } catch (Throwable $e) {
                Craft::error('The email could not be sent: ' . $e->getMessage(), 'security-alerts');

                return 0;
            }
        }
        $this->store->markNotified($pending);

        return count($toSend);
    }

    /**
     * @param list<Finding> $findings
     * @param list<string> $recipients
     */
    private function send(array $findings, array $recipients): void
    {
        $exploited = array_values(array_filter($findings, static fn(Finding $f): bool => $f->exploited));
        $others = array_values(array_filter($findings, static fn(Finding $f): bool => !$f->exploited));

        $sent = $this->mailer->compose()
            ->setTo($recipients)
            ->setSubject($this->subject(count($exploited), count($findings)))
            ->setHtmlBody($this->html($exploited, $others))
            ->setTextBody($this->text($exploited, $others))
            ->send();
        if (!$sent) {
            throw new \RuntimeException('The mailer did not accept the message.');
        }
    }

    public function subject(int $exploited, int $total): string
    {
        if ($exploited > 0) {
            return sprintf(
                'Exploited — patch now: %d known %s on %s',
                $exploited,
                $exploited === 1 ? 'vulnerability is being exploited' : 'vulnerabilities are being exploited',
                $this->siteName,
            );
        }

        return sprintf('%d new security %s for %s', $total, $total === 1 ? 'advisory' : 'advisories', $this->siteName);
    }

    /**
     * @param list<Finding> $exploited
     * @param list<Finding> $others
     */
    private function html(array $exploited, array $others): string
    {
        $html = '<div style="font-family:-apple-system,Segoe UI,Helvetica,Arial,sans-serif;font-size:15px;line-height:1.6;color:#16162a">';
        if ($exploited !== []) {
            $html .= '<p style="margin:0 0 6px;color:#e5384f"><strong>Exploited — patch now</strong></p>'
                . '<p style="margin:0 0 14px">These are on the CISA list of vulnerabilities known to be exploited in the wild.</p>'
                . $this->block($exploited);
        }
        if ($others !== []) {
            $html .= '<p style="margin:18px 0 6px"><strong>New security advisories</strong></p>' . $this->block($others);
        }
        if ($this->utilityUrl !== null) {
            $html .= '<p style="margin:18px 0 0"><a href="' . Html::encode($this->utilityUrl) . '">Open Security alerts in the control panel</a></p>';
        }

        return $html . '</div>';
    }

    /**
     * One paragraph per finding. Everything from an advisory is escaped.
     *
     * @param list<Finding> $findings
     */
    private function block(array $findings): string
    {
        $html = '';
        foreach ($findings as $finding) {
            $title = Html::encode($finding->title);
            if ($finding->safeLink() !== null) {
                $title = '<a href="' . Html::encode($finding->safeLink()) . '">' . $title . '</a>';
            }
            $html .= '<p style="margin:0 0 14px"><strong>' . $title . '</strong><br>'
                . implode(' · ', array_map(static fn(string $f): string => Html::encode($f), $this->facts($finding))) . '</p>';
        }

        return $html;
    }

    /**
     * @param list<Finding> $exploited
     * @param list<Finding> $others
     */
    private function text(array $exploited, array $others): string
    {
        $lines = [];
        if ($exploited !== []) {
            $lines[] = 'EXPLOITED — PATCH NOW (on the CISA list of vulnerabilities known to be exploited)';
            $lines[] = '';
            array_push($lines, ...$this->textLines($exploited));
        }
        if ($others !== []) {
            $lines[] = 'New security advisories';
            $lines[] = '';
            array_push($lines, ...$this->textLines($others));
        }
        if ($this->utilityUrl !== null) {
            $lines[] = 'Security alerts in the control panel: ' . $this->utilityUrl;
        }

        return implode("\n", $lines) . "\n";
    }

    /**
     * @param list<Finding> $findings
     * @return list<string>
     */
    private function textLines(array $findings): array
    {
        $lines = [];
        foreach ($findings as $finding) {
            $lines[] = $finding->title;
            $lines[] = '  ' . implode(' · ', $this->facts($finding));
            if ($finding->safeLink() !== null) {
                $lines[] = '  ' . $finding->safeLink();
            }
            $lines[] = '';
        }

        return $lines;
    }

    /**
     * @return list<string>
     */
    private function facts(Finding $finding): array
    {
        $facts = [$finding->package . ' ' . $finding->installedVersion];
        if ($finding->cve !== null) {
            $facts[] = $finding->cve;
        }
        $facts[] = $finding->severityLevel()->label() . ($finding->severity === null ? ' (not rated)' : '');
        $facts[] = $finding->fixedPhrase();

        return $facts;
    }
}
