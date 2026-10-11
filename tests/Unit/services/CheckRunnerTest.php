<?php

declare(strict_types=1);

namespace ruvelo\securityalerts\tests\Unit\services;

use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use ruvelo\securityalerts\exceptions\SourceException;
use ruvelo\securityalerts\models\Changes;
use ruvelo\securityalerts\models\CheckOutcome;
use ruvelo\securityalerts\models\Finding;
use ruvelo\securityalerts\models\ScanResult;
use ruvelo\securityalerts\services\Checker;
use ruvelo\securityalerts\services\CheckRunner;
use ruvelo\securityalerts\services\Scanner;
use ruvelo\securityalerts\tests\Fake\Findings;

class CheckRunnerTest extends TestCase
{
    /** @var list<string> */
    private array $out = [];

    /** @var list<string> */
    private array $err = [];

    /**
     * @param list<Finding> $findings
     * @param list<string> $warnings
     * @return array{CheckRunner, Checker&MockObject, Scanner&MockObject}
     */
    private function runner(array $findings, ?SourceException $error = null, array $warnings = []): array
    {
        $result = new ScanResult($findings, $warnings, 42);
        $checker = $this->createMock(Checker::class);
        $scanner = $this->createMock(Scanner::class);
        if ($error !== null) {
            $checker->method('run')->willThrowException($error);
            $scanner->method('scan')->willThrowException($error);
        } else {
            $checker->method('run')->willReturn(new CheckOutcome($result, new Changes([], [], 0), 0));
            $scanner->method('scan')->willReturn($result);
        }

        return [new CheckRunner($scanner, $checker), $checker, $scanner];
    }

    private function exec(CheckRunner $runner, bool $json = false, ?string $failOn = null, bool $dryRun = false): int
    {
        $this->out = [];
        $this->err = [];

        return $runner->run(
            $json,
            $failOn,
            $dryRun,
            function(string $line): void {
                $this->out[] = $line;
            },
            function(string $line): void {
                $this->err[] = $line;
            },
        );
    }

    public function testCleanSiteExitsZeroEvenWithFailOnAny(): void
    {
        [$runner] = $this->runner([]);

        $this->assertSame(0, $this->exec($runner, failOn: 'any'));
        $this->assertSame(['No known vulnerabilities found in 42 packages.'], $this->out);
    }

    public function testFailOnExploitedIgnoresOtherFindings(): void
    {
        [$runner] = $this->runner([Findings::make()]);

        $this->assertSame(0, $this->exec($runner, failOn: 'exploited'));
    }

    public function testFailOnExploitedFailsOnAnExploitedFinding(): void
    {
        [$runner] = $this->runner([Findings::make(exploited: true)]);

        $this->assertSame(1, $this->exec($runner, failOn: 'exploited'));
        $this->assertStringContainsString('EXPLOITED — PATCH NOW acme/craft-widgets 1.2.0: A flaw', $this->out[0]);
    }

    public function testFailOnAnyFailsOnAnyFinding(): void
    {
        [$runner] = $this->runner([Findings::make()]);

        $this->assertSame(1, $this->exec($runner, failOn: 'any'));
    }

    public function testWithoutFailOnFindingsDoNotChangeTheExitCode(): void
    {
        [$runner] = $this->runner([Findings::make(exploited: true)]);

        $this->assertSame(0, $this->exec($runner));
    }

    public function testRejectsAnUnknownFailOnBeforeDoingAnything(): void
    {
        [$runner, $checker, $scanner] = $this->runner([]);
        $checker->expects($this->never())->method('run');
        $scanner->expects($this->never())->method('scan');

        $this->assertSame(2, $this->exec($runner, failOn: 'high'));
        $this->assertSame(['--fail-on must be "exploited" or "any".'], $this->err);
    }

    public function testJsonOutputIsMachineReadable(): void
    {
        [$runner] = $this->runner(
            [Findings::make(exploited: true, title: 'Remote code execution'), Findings::make(advisory: 'PKSA-2', severity: null)],
            null,
            ['CISA was slow'],
        );

        $code = $this->exec($runner, json: true, failOn: 'exploited');

        $this->assertSame(1, $code);
        $this->assertCount(1, $this->out);
        $data = json_decode($this->out[0], true, 512, JSON_THROW_ON_ERROR);
        $this->assertSame(1, $data['exploited']);
        $this->assertSame(2, $data['total']);
        $this->assertSame(42, $data['packages_checked']);
        $this->assertSame(['CISA was slow'], $data['warnings']);
        $this->assertSame('Remote code execution', $data['findings'][0]['title']);
        $this->assertTrue($data['findings'][0]['exploited']);
        $this->assertNull($data['findings'][1]['severity']);
        $this->assertSame('high', $data['findings'][1]['severity_level']);
    }

    public function testJsonForACleanSiteIsStillValid(): void
    {
        [$runner] = $this->runner([]);

        $this->exec($runner, json: true);

        $data = json_decode($this->out[0], true, 512, JSON_THROW_ON_ERROR);
        $this->assertSame(['exploited' => 0, 'total' => 0, 'packages_checked' => 42, 'warnings' => [], 'findings' => []], $data);
    }

    public function testDryRunOnlyScans(): void
    {
        [$runner, $checker, $scanner] = $this->runner([Findings::make()]);
        $checker->expects($this->never())->method('run');
        $scanner->expects($this->once())->method('scan');

        $this->exec($runner, dryRun: true);
    }

    public function testASourceFailureExitsTwoAndWritesNothingToStdout(): void
    {
        [$runner] = $this->runner([], new SourceException('Packagist is down.'));

        $this->assertSame(2, $this->exec($runner, json: true, failOn: 'any'));
        $this->assertSame(['Packagist is down.'], $this->err);
        $this->assertSame([], $this->out);
    }

    public function testWarningsAreShownInTextMode(): void
    {
        [$runner] = $this->runner([], null, ['composer.lock was not found']);

        $this->exec($runner);

        $this->assertSame('Warning: composer.lock was not found', $this->out[0]);
    }
}
