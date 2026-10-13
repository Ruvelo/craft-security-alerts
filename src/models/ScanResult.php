<?php

declare(strict_types=1);

namespace ruvelo\securityalerts\models;

use Ruvelo\SecurityAdvisories\Report;

class ScanResult
{
    /**
     * @param list<Finding> $findings Exploited first, then by severity
     * @param list<string> $warnings Things that did not work but did not stop the check
     * @param Report|null $report What the shared core found, which the reconciler compares with what is stored
     */
    public function __construct(
        public readonly array $findings,
        public readonly array $warnings,
        public readonly int $packagesChecked,
        public readonly ?Report $report = null,
    ) {
    }

    /**
     * @return list<Finding>
     */
    public function exploited(): array
    {
        return array_values(array_filter($this->findings, static fn(Finding $f): bool => $f->exploited));
    }

    /**
     * Which path answered: "valtry", "public" or "mixed". Null when the result did not come from a scan.
     */
    public function source(): ?string
    {
        return $this->report?->source;
    }

    /**
     * Where the answers came from, in words: "Valtry Advisory API (signed answers)" or "public feeds (Packagist and CISA)".
     */
    public function sourceLabel(): ?string
    {
        $source = $this->source();

        return $source !== null ? SourceLabel::long($source) : null;
    }
}
