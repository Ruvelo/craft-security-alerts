<?php

declare(strict_types=1);

namespace ruvelo\securityalerts\services;

use ruvelo\securityalerts\exceptions\SourceException;
use ruvelo\securityalerts\models\Finding;
use ruvelo\securityalerts\models\Findings;
use ruvelo\securityalerts\models\ScanResult;
use ruvelo\securityalerts\sources\AdvisoryClient;
use ruvelo\securityalerts\sources\KevCatalogue;

/**
 * Works out which known vulnerabilities apply to this site right now. Reads, never writes.
 */
class Scanner
{
    public const CORE_PACKAGE = 'craftcms/cms';

    /**
     * @param string|null $coreVersion Craft's own idea of its version, used when composer.lock does not list it
     */
    public function __construct(
        private readonly ComposerLock $composerLock,
        private readonly AdvisoryClient $advisories,
        private readonly KevCatalogue $kev,
        private readonly AdvisoryMatcher $matcher,
        private readonly ?string $coreVersion = null,
    ) {
    }

    /**
     * @throws SourceException When Packagist cannot be reached: without it there is no answer to give
     */
    public function scan(): ScanResult
    {
        $warnings = [];
        $installed = [];

        try {
            $installed = $this->composerLock->packages();
        } catch (SourceException $e) {
            $warnings[] = $e->getMessage();
        }

        if (!isset($installed[self::CORE_PACKAGE])) {
            $core = $this->coreVersion !== null ? trim($this->coreVersion) : '';
            if (preg_match('/^\d+\.\d+/', $core) === 1) {
                $installed[self::CORE_PACKAGE] = $core;
            } else {
                $warnings[] = 'The Craft version could not be read, so core advisories were not checked.';
            }
        }
        if ($installed === []) {
            throw new SourceException('There is nothing to check: no Craft version and no composer.lock.');
        }

        $advisories = $this->advisories->fetch(array_keys($installed));

        try {
            $exploitedCves = $this->kev->exploitedCves();
        } catch (SourceException $e) {
            $exploitedCves = [];
            $warnings[] = 'The CISA exploited-vulnerabilities list could not be fetched, so nothing is flagged as exploited this time: '
                . $e->getMessage();
        }

        $findings = [];
        foreach ($advisories as $package => $list) {
            if (!isset($installed[$package])) {
                continue;
            }
            foreach ($list as $advisory) {
                $finding = $this->toFinding($package, $installed[$package], $advisory, $exploitedCves);
                if ($finding !== null) {
                    $findings[$finding->key()] = $finding;
                }
            }
        }

        return new ScanResult(Findings::sorted(array_values($findings)), $warnings, count($installed));
    }

    /**
     * @param array<string, mixed> $advisory
     * @param array<string, true> $exploitedCves
     */
    private function toFinding(string $package, string $version, array $advisory, array $exploitedCves): ?Finding
    {
        $constraint = $advisory['affectedVersions'] ?? null;
        $id = $advisory['advisoryId'] ?? null;
        if (!is_string($constraint) || !is_string($id) || !$this->matcher->affects($version, $constraint)) {
            return null;
        }
        $cve = $this->text($advisory['cve'] ?? null);

        return new Finding(
            $package,
            $version,
            $id,
            $this->text($advisory['title'] ?? null) ?? $id,
            $this->text($advisory['link'] ?? null),
            $cve,
            $this->text($advisory['severity'] ?? null),
            $this->matcher->fixedIn($version, $constraint),
            $cve !== null && isset($exploitedCves[strtoupper($cve)]),
            fixedAfter: $this->matcher->fixedAfter($version, $constraint),
        );
    }

    private function text(mixed $value): ?string
    {
        return is_string($value) && trim($value) !== '' ? trim($value) : null;
    }
}
