<?php

declare(strict_types=1);

namespace ruvelo\securityalerts\services;

use ruvelo\securityalerts\exceptions\SourceException;
use ruvelo\securityalerts\models\Finding;
use ruvelo\securityalerts\models\ScanResult;

/**
 * The logic behind `php craft security-alerts/check`, apart from the console plumbing, so that it can be tested.
 */
class CheckRunner
{
    public const EXIT_OK = 0;
    public const EXIT_FINDINGS = 1;
    public const EXIT_ERROR = 2;

    public function __construct(private readonly Scanner $scanner, private readonly Checker $checker)
    {
    }

    /**
     * @param callable(string): mixed $out Normal output
     * @param callable(string): mixed $err Errors
     * @return int Exit code: 0 fine, 1 a finding matched --fail-on, 2 a source failed or an option is wrong
     */
    public function run(bool $json, ?string $failOn, bool $dryRun, callable $out, callable $err): int
    {
        if ($failOn !== null && !in_array($failOn, ['exploited', 'any'], true)) {
            $err('--fail-on must be "exploited" or "any".');

            return self::EXIT_ERROR;
        }

        try {
            $result = $dryRun ? $this->scanner->scan() : $this->checker->run()->result;
        } catch (SourceException $e) {
            $err($e->getMessage());

            return self::EXIT_ERROR;
        }

        if ($json) {
            $out($this->json($result));
        } else {
            foreach ($this->text($result) as $line) {
                $out($line);
            }
        }

        $failed = ($failOn === 'any' && $result->findings !== [])
            || ($failOn === 'exploited' && $result->exploited() !== []);

        return $failed ? self::EXIT_FINDINGS : self::EXIT_OK;
    }

    public function json(ScanResult $result): string
    {
        return (string)json_encode([
            'exploited' => count($result->exploited()),
            'total' => count($result->findings),
            'packages_checked' => $result->packagesChecked,
            'warnings' => $result->warnings,
            'findings' => array_map(static fn(Finding $f): array => $f->toArray(), $result->findings),
        ], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    }

    /**
     * @return list<string>
     */
    public function text(ScanResult $result): array
    {
        $lines = [];
        foreach ($result->warnings as $warning) {
            $lines[] = 'Warning: ' . $warning;
        }
        if ($result->findings === []) {
            $lines[] = sprintf('No known vulnerabilities found in %d packages.', $result->packagesChecked);

            return $lines;
        }

        foreach ($result->findings as $f) {
            $lines[] = sprintf(
                '%s %s %s: %s',
                $f->exploited ? 'EXPLOITED — PATCH NOW' : strtoupper($f->severityLevel()->value),
                $f->package,
                $f->installedVersion,
                $f->title,
            );
            $lines[] = sprintf(
                '    %s | %s | %s',
                $f->cve ?? 'no CVE',
                $f->fixedPhrase(),
                $f->link ?? 'no link',
            );
        }
        $lines[] = sprintf(
            "\n%d findings, %d exploited, in %d packages checked.",
            count($result->findings),
            count($result->exploited()),
            $result->packagesChecked,
        );

        return $lines;
    }
}
