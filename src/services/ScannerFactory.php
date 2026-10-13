<?php

declare(strict_types=1);

namespace ruvelo\securityalerts\services;

use Craft;
use GuzzleHttp\Psr7\HttpFactory;
use Ruvelo\SecurityAdvisories\Cache\FileCache;
use Ruvelo\SecurityAdvisories\Cache\ResponseCache;
use Ruvelo\SecurityAdvisories\Cache\Ttls;
use Ruvelo\SecurityAdvisories\Http\JsonClient;
use Ruvelo\SecurityAdvisories\Packages\ComposerLockReader;
use Ruvelo\SecurityAdvisories\Scanner as Core;
use Ruvelo\SecurityAdvisories\Sources\FallbackAdvisorySource;
use Ruvelo\SecurityAdvisories\Sources\KevCatalogue;
use Ruvelo\SecurityAdvisories\Sources\PackagistAdvisorySource;
use Ruvelo\SecurityAdvisories\Valtry\ValtryAdvisorySource;
use ruvelo\securityalerts\models\Settings;

/**
 * Wires the shared core to Craft: composer.lock from the project root, Craft's own Guzzle client
 * (so a configured proxy applies) as the PSR-18 client, and a file cache under storage/runtime.
 */
class ScannerFactory
{
    public const USER_AGENT = 'ruvelo/craft-security-alerts (+https://github.com/Ruvelo/craft-security-alerts)';

    private const TIMEOUT_SECONDS = 20;

    public static function create(Settings $settings): Scanner
    {
        $factory = new HttpFactory();

        return self::build(
            $settings,
            new JsonClient(self::client(self::TIMEOUT_SECONDS), $factory, $factory, self::USER_AGENT),
            new JsonClient(self::client(ValtryAdvisorySource::DEADLINE), $factory, $factory, self::USER_AGENT, 1),
            new ResponseCache(new FileCache(Craft::getAlias('@storage/runtime/security-alerts')), new Ttls()),
            Craft::getAlias('@root/composer.lock'),
            Craft::$app->getVersion(),
        );
    }

    /**
     * The wiring without Craft's services, so that it can be tested with a fake HTTP client.
     *
     * @param JsonClient $http For Packagist and the CISA catalogue
     * @param JsonClient $valtryHttp For Valtry, with its own short timeout
     * @param array<string, string>|null $valtryKeys Only tests, which sign their own answers, say otherwise
     */
    public static function build(
        Settings $settings,
        JsonClient $http,
        JsonClient $valtryHttp,
        ResponseCache $cache,
        string $lockPath,
        ?string $craftVersion,
        ?array $valtryKeys = null,
        string $valtryUrl = ValtryAdvisorySource::URL,
    ): Scanner {
        $public = [new PackagistAdvisorySource($http, $cache)];
        $advisories = $settings->usesPublicFeedsOnly()
            ? $public
            : [new FallbackAdvisorySource(new ValtryAdvisorySource($valtryHttp, $cache, $valtryUrl, $valtryKeys), $public)];

        // Runtime packages only: dev packages are not installed on a production site.
        $packages = new CraftPackages(new ComposerLockReader($lockPath, false), $craftVersion);

        return new Scanner(new Core([$packages], $advisories, new KevCatalogue($http, $cache)), $packages);
    }

    private static function client(float $timeout): \GuzzleHttp\Client
    {
        return Craft::createGuzzleClient([
            'timeout' => $timeout,
            'connect_timeout' => min(5.0, $timeout),
            'http_errors' => false,
        ]);
    }
}
