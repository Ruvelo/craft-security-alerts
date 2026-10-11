<?php

declare(strict_types=1);

namespace ruvelo\securityalerts\tests\Unit\services;

use PHPUnit\Framework\TestCase;
use ruvelo\securityalerts\exceptions\SourceException;
use ruvelo\securityalerts\services\ComposerLock;

class ComposerLockTest extends TestCase
{
    public function testReadsExactVersionsFromRuntimePackagesOnly(): void
    {
        $packages = (new ComposerLock(__DIR__ . '/../../_files/composer.lock'))->packages();

        $this->assertSame('5.6.10', $packages['craftcms/cms']);
        $this->assertSame('5.3.0', $packages['craftcms/commerce']);
        $this->assertSame('v1.2.0', $packages['acme/craft-widgets']);
        $this->assertArrayNotHasKey('phpunit/phpunit', $packages, 'packages-dev is not installed in production');
    }

    public function testDevBranchesAreNeitherReadNorSent(): void
    {
        $packages = (new ComposerLock(__DIR__ . '/../../_files/composer.lock'))->packages();

        $this->assertArrayNotHasKey('acme/private-thing', $packages);
        $this->assertArrayNotHasKey('acme/branch-thing', $packages);
    }

    public function testMissingFileIsASourceError(): void
    {
        $this->expectException(SourceException::class);
        $this->expectExceptionMessage('composer.lock was not found');

        (new ComposerLock('/nonexistent/composer.lock'))->packages();
    }

    public function testInvalidJsonIsASourceError(): void
    {
        $path = tempnam(sys_get_temp_dir(), 'lock');
        file_put_contents($path, '{nope');

        try {
            $this->expectException(SourceException::class);
            $this->expectExceptionMessage('not valid JSON');
            (new ComposerLock($path))->packages();
        } finally {
            unlink($path);
        }
    }
}
