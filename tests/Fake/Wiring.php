<?php

declare(strict_types=1);

namespace ruvelo\securityalerts\tests\Fake;

use GuzzleHttp\Psr7\HttpFactory;
use Ruvelo\SecurityAdvisories\Cache\ResponseCache;
use Ruvelo\SecurityAdvisories\Http\JsonClient;
use ruvelo\securityalerts\models\Settings;
use ruvelo\securityalerts\services\Scanner;
use ruvelo\securityalerts\services\ScannerFactory;

/**
 * The production wiring (ScannerFactory::build) around a fake HTTP client and a lock file from the fixtures.
 */
class Wiring
{
    public const LOCK = __DIR__ . '/../_files/composer.lock';

    /**
     * A composer.lock with exactly these packages (name => version), in the temp directory.
     *
     * @param array<string, string> $packages
     */
    public static function lock(array $packages): string
    {
        $path = tempnam(sys_get_temp_dir(), 'sa-lock');
        $list = [];
        foreach ($packages as $name => $version) {
            $list[] = ['name' => $name, 'version' => $version];
        }
        file_put_contents($path, json_encode(['packages' => $list, 'packages-dev' => []]));

        return $path;
    }

    public static function scanner(FakeClient $client, string $source = 'public', string $lock = self::LOCK, ?string $craftVersion = '5.6.10'): Scanner
    {
        $factory = new HttpFactory();
        // No cache: every scan asks the fake, so the requests it records are the whole story.
        $http = new JsonClient($client, $factory, $factory, ScannerFactory::USER_AGENT, 1);

        return ScannerFactory::build(
            new Settings(['advisorySource' => $source]),
            $http,
            $http,
            new ResponseCache(),
            $lock,
            $craftVersion,
            $client->keys(),
            FakeClient::VALTRY_URL,
        );
    }
}
