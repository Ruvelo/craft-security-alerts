<?php

declare(strict_types=1);

namespace ruvelo\securityalerts\tests\Fake;

use DateTimeImmutable;
use Ruvelo\SecurityAdvisories\Ecosystem;
use Ruvelo\SecurityAdvisories\Finding as CoreFinding;
use Ruvelo\SecurityAdvisories\KevEntry;
use Ruvelo\SecurityAdvisories\Report;
use Ruvelo\SecurityAdvisories\Severity;
use ruvelo\securityalerts\models\Finding;
use ruvelo\securityalerts\models\ScanResult;

class Findings
{
    public static function make(
        string $package = 'acme/craft-widgets',
        string $advisory = 'PKSA-1',
        bool $exploited = false,
        ?string $severity = 'high',
        string $installed = '1.2.0',
        string $title = 'A flaw',
    ): Finding {
        return new Finding(
            $package,
            $installed,
            $advisory,
            $title,
            'https://example.com/' . $advisory,
            'CVE-2099-' . substr($advisory, -4),
            $severity,
            '9.9.9',
            $exploited,
        );
    }

    /**
     * What a scan returns for these findings: the core's report inside, as the reconciler needs it.
     *
     * @param list<Finding> $findings
     * @param list<string> $problems Anything here makes the report incomplete, so nothing resolves
     * @param list<string> $aliases Other ids every finding is known by
     */
    public static function result(array $findings, array $problems = [], string $origin = 'public', array $aliases = []): ScanResult
    {
        $core = array_map(static fn(Finding $f): CoreFinding => new CoreFinding(
            Ecosystem::Composer,
            $f->package,
            $f->installedVersion,
            $f->advisoryId,
            $f->title,
            Severity::parse($f->severity),
            $f->link,
            $f->cve,
            $f->fixedIn,
            exploited: $f->exploited ? new KevEntry((string)$f->cve, 'Exploited', new DateTimeImmutable('2026-09-01')) : null,
            aliases: $aliases,
        ), $findings);
        $report = new Report($core, ['composer' => 10], [Ecosystem::Composer], $problems, true, null, ['composer' => $origin]);

        return new ScanResult($findings, $problems, 10, $report);
    }
}
