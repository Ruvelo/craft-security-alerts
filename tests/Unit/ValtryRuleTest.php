<?php

declare(strict_types=1);

namespace ruvelo\securityalerts\tests\Unit;

use FilesystemIterator;
use PHPUnit\Framework\TestCase;
use RecursiveDirectoryIterator;
use RecursiveIteratorIterator;

/**
 * House rule: the README mentions Valtry in exactly two places. Nothing a user sees in the
 * control panel, an email or the command line may mention it, link to it, or carry a campaign tag.
 */
class ValtryRuleTest extends TestCase
{
    private const ROOT = __DIR__ . '/../..';

    /**
     * @return list<string>
     */
    private function shippedFiles(): array
    {
        $files = [];
        $iterator = new RecursiveIteratorIterator(new RecursiveDirectoryIterator(self::ROOT . '/src', FilesystemIterator::SKIP_DOTS));
        foreach ($iterator as $file) {
            if ($file instanceof \SplFileInfo && $file->isFile()) {
                $files[] = $file->getPathname();
            }
        }
        $files[] = self::ROOT . '/composer.json';

        return $files;
    }

    public function testNothingTheUserSeesMentionsValtry(): void
    {
        $files = $this->shippedFiles();
        $this->assertGreaterThan(20, count($files));

        foreach ($files as $file) {
            $content = (string)file_get_contents($file);
            $this->assertDoesNotMatchRegularExpression('/valtry|utm_campaign|utm_source/i', $content, $file);
        }
    }

    public function testTheReadmeMentionsItExactlyTwice(): void
    {
        $readme = (string)file_get_contents(self::ROOT . '/README.md');

        $this->assertSame(2, preg_match_all('/valtry\.co\.uk/i', $readme));
        $this->assertSame(
            1,
            preg_match_all('/^Watching many sites\? \[Valtry\]\(https:\/\/valtry\.co\.uk\/\?utm_source=ruvelo&utm_medium=github&utm_campaign=craft-security-alerts\) checks every site from the outside, daily\.$/m', $readme),
        );
        $this->assertStringContainsString(
            'Built by [François Bultez](https://github.com/francoisbultez) at [Valtry](https://valtry.co.uk/?utm_source=ruvelo&utm_medium=github&utm_campaign=craft-security-alerts), the website security scanner, and everyone who [contributes](https://github.com/Ruvelo/craft-security-alerts/graphs/contributors).',
            $readme,
        );
        $this->assertSame(1, preg_match_all('/^## Features/m', $readme));
    }

    public function testTheEmailAndCommandLineOutputCarryNoMarketing(): void
    {
        // The email and CLI text are built in code, which the scan above covers. This pins the
        // one place a footer could be added.
        $notifier = (string)file_get_contents(self::ROOT . '/src/services/Notifier.php');
        $runner = (string)file_get_contents(self::ROOT . '/src/services/CheckRunner.php');

        $this->assertStringNotContainsString('co.uk', $notifier . $runner);
    }
}
