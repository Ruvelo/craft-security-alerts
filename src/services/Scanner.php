<?php

declare(strict_types=1);

namespace ruvelo\securityalerts\services;

use Ruvelo\SecurityAdvisories\Ecosystem;
use Ruvelo\SecurityAdvisories\Scanner as Core;
use ruvelo\securityalerts\exceptions\SourceException;
use ruvelo\securityalerts\models\Finding;
use ruvelo\securityalerts\models\Findings;
use ruvelo\securityalerts\models\ScanResult;

/**
 * Works out which known vulnerabilities apply to this site right now. Reads, never writes.
 * Reading, asking, matching and marking what is exploited are the shared core's.
 */
class Scanner
{
    public const CORE_PACKAGE = CraftPackages::CORE_PACKAGE;

    public function __construct(
        private readonly Core $core,
        private readonly CraftPackages $packages,
    ) {
    }

    /**
     * @throws SourceException When the packages could not be checked at all: without an answer there is nothing to give
     */
    public function scan(bool $fresh = false): ScanResult
    {
        $report = $this->core->scan($fresh);

        if (!$report->isCheckedFor(Ecosystem::Composer)) {
            throw new SourceException(implode(' ', [...$this->packages->warnings(), ...$report->problems]));
        }

        $warnings = [...$this->packages->warnings(), ...$report->problems];
        foreach ($report->notes as $note) {
            $warnings[] = $note->message;
        }

        return new ScanResult(
            Findings::sorted(array_map(static fn($f): Finding => Finding::fromCore($f), $report->findings)),
            $warnings,
            $report->packageCount(),
            $report,
        );
    }
}
