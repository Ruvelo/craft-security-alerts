<?php

declare(strict_types=1);

namespace ruvelo\securityalerts\services;

use ruvelo\securityalerts\exceptions\SourceException;

/**
 * Reads the exact installed versions from the project's composer.lock.
 */
class ComposerLock
{
    public function __construct(private readonly string $path)
    {
    }

    /**
     * Runtime packages only: Craft, its plugins and everything they pull in. `packages-dev`
     * is not installed on a production site, so it is neither checked nor sent anywhere.
     * Dev branches (`dev-main`, `1.x-dev`) have no version to match and are not sent either.
     *
     * @return array<string, string> Package name => installed version
     * @throws SourceException
     */
    public function packages(): array
    {
        if (!is_file($this->path)) {
            throw new SourceException('composer.lock was not found in the project root, so plugins cannot be checked.');
        }
        $json = @file_get_contents($this->path);
        if ($json === false) {
            throw new SourceException('composer.lock could not be read.');
        }

        $lock = json_decode($json, true);
        if (!is_array($lock) || !isset($lock['packages']) || !is_array($lock['packages'])) {
            throw new SourceException('composer.lock is not valid JSON.');
        }

        $packages = [];
        foreach ($lock['packages'] as $package) {
            if (!is_array($package) || !isset($package['name'], $package['version'])
                || !is_string($package['name']) || !is_string($package['version'])
                || str_starts_with($package['version'], 'dev-')
                || str_ends_with($package['version'], '-dev')
            ) {
                continue;
            }
            $packages[$package['name']] = $package['version'];
        }

        return $packages;
    }
}
