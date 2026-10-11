<?php

declare(strict_types=1);

namespace ruvelo\securityalerts\tests\Unit\services;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use ruvelo\securityalerts\services\AdvisoryMatcher;

class AdvisoryMatcherTest extends TestCase
{
    /** CVE-2025-32432 in the shape Packagist lists it: one range per release line. */
    private const CRAFT_RCE = '>=3.0.0-RC1,<3.9.15|>=4.0.0-RC1,<4.14.15|>=5.0.0-RC1,<5.6.17';

    /** Magento-style patch lines, which the shared matcher also has to follow. */
    private const PATCH_LINES = '<2.4.4|>=2.4.4,<2.4.4-p9|>=2.4.5,<2.4.5-p8|>=2.4.6,<2.4.6-p6|>=2.4.7,<2.4.7-p1';

    private const WITH_EXACT = '=2.4.6|=2.4.7|=2.4.8|<2.4.6-p13|>=2.4.7-beta1,<2.4.7-p8|>=2.4.8-beta1,<2.4.8-p3';

    /**
     * @return array<string, array{string, string, bool}>
     */
    public static function affected(): array
    {
        return [
            'craft 5 before the fix' => ['5.6.16', self::CRAFT_RCE, true],
            'craft 5 fixed' => ['5.6.17', self::CRAFT_RCE, false],
            'craft 5 later' => ['5.8.2', self::CRAFT_RCE, false],
            'craft 4 before its own fix' => ['4.14.14', self::CRAFT_RCE, true],
            'craft 4 fixed' => ['4.14.15', self::CRAFT_RCE, false],
            'craft 3 line' => ['3.9.14', self::CRAFT_RCE, true],
            'a four-part version, as Composer writes Craft releases' => ['5.6.10.1', self::CRAFT_RCE, true],
            'a release candidate of the next line' => ['5.0.0-RC1', self::CRAFT_RCE, true],
            'before the first patch line' => ['2.4.7', self::PATCH_LINES, true],
            'patched' => ['2.4.7-p1', self::PATCH_LINES, false],
            'exact release listed' => ['2.4.8', self::WITH_EXACT, true],
            'a dev branch cannot be compared' => ['dev-main', self::CRAFT_RCE, false],
            'a v prefix is fine' => ['v1.2.0', '>=1.0.0,<1.4.2', true],
            'garbage constraint' => ['1.0.0', 'not a constraint !!', false],
        ];
    }

    #[DataProvider('affected')]
    public function testAffects(string $version, string $constraint, bool $expected): void
    {
        $this->assertSame($expected, (new AdvisoryMatcher())->affects($version, $constraint));
    }

    /**
     * @return array<string, array{string, string, string|null}>
     */
    public static function fixes(): array
    {
        return [
            'craft 5 fix is on its own line' => ['5.6.10', self::CRAFT_RCE, '5.6.17'],
            'craft 4 fix is on its own line' => ['4.2.0', self::CRAFT_RCE, '4.14.15'],
            'next patch on the same line' => ['2.4.7', self::PATCH_LINES, '2.4.7-p1'],
            'follows the chain past a bare release' => ['2.4.3', self::PATCH_LINES, '2.4.4-p9'],
            'a beta is fixed by the first patch' => ['2.4.7-beta1', self::WITH_EXACT, '2.4.7-p8'],
            'nothing to follow for an exact release' => ['2.4.7', '=2.4.7', null],
            'a third-party range' => ['1.2.0', '>=1.0.0,<1.4.2', '1.4.2'],
            'less-or-equal bound is not a fix version' => ['1.2.0', '<=1.4.2', null],
            'not affected at all' => ['3.0.0', '>=1.0.0,<1.4.2', null],
        ];
    }

    /**
     * @return array<string, array{string, string, string|null}>
     */
    public static function fixedAfter(): array
    {
        $realShape = '>=5.0.0-RC1,<=5.6.16|>=4.0.0-RC1,<=4.14.14';

        return [
            'only a last affected version is known' => ['5.6.10', $realShape, '5.6.16'],
            'on the other release line' => ['4.2.0', $realShape, '4.14.14'],
            'a strict bound has nothing to report' => ['5.6.10', self::CRAFT_RCE, null],
            'not affected' => ['5.8.0', $realShape, null],
        ];
    }

    #[DataProvider('fixedAfter')]
    public function testFixedAfter(string $version, string $constraint, ?string $expected): void
    {
        $this->assertSame($expected, (new AdvisoryMatcher())->fixedAfter($version, $constraint));
    }

    #[DataProvider('fixes')]
    public function testFixedIn(string $version, string $constraint, ?string $expected): void
    {
        $this->assertSame($expected, (new AdvisoryMatcher())->fixedIn($version, $constraint));
    }
}
