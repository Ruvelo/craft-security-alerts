<?php

declare(strict_types=1);

namespace ruvelo\securityalerts\services;

use Ruvelo\SecurityAdvisories\Ecosystem;
use Ruvelo\SecurityAdvisories\Exceptions\PackagesUnreadable;
use Ruvelo\SecurityAdvisories\InstalledPackage;
use Ruvelo\SecurityAdvisories\Packages\PackageSource;

/**
 * What a Craft site runs: the packages in composer.lock, and Craft itself even when the lock
 * does not list it (a project that keeps its lock elsewhere still gets its core checked).
 *
 * A lock that is missing or unreadable is a warning here, not a failure: Craft's own version
 * is still worth checking. Packages on a dev branch have no version to match and are left out.
 */
class CraftPackages implements PackageSource
{
    public const CORE_PACKAGE = 'craftcms/cms';

    /** @var list<string> */
    private array $warnings = [];

    /**
     * @param string|null $craftVersion Craft's own idea of its version, used when the lock does not list it
     */
    public function __construct(private readonly PackageSource $lock, private readonly ?string $craftVersion = null)
    {
    }

    /**
     * What could not be read during the last call, to show as warnings.
     *
     * @return list<string>
     */
    public function warnings(): array
    {
        return $this->warnings;
    }

    public function ecosystem(): Ecosystem
    {
        return Ecosystem::Composer;
    }

    public function describe(): string
    {
        return 'a Craft version or a readable composer.lock';
    }

    public function isRequired(): bool
    {
        return true;
    }

    public function packages(): ?array
    {
        $this->warnings = [];
        $list = [];

        try {
            $read = $this->lock->packages();
            if ($read === null) {
                $this->warnings[] = 'composer.lock was not found in the project root, so plugins cannot be checked.';
            }
            $list = $read ?? [];
        } catch (PackagesUnreadable $e) {
            $this->warnings[] = $e->getMessage();
        }

        $list = array_values(array_filter(
            $list,
            static fn(InstalledPackage $p): bool => !str_starts_with($p->version, 'dev-') && !str_ends_with($p->version, '-dev'),
        ));

        $hasCore = array_filter($list, static fn(InstalledPackage $p): bool => $p->name === self::CORE_PACKAGE) !== [];
        if (!$hasCore) {
            $core = $this->craftVersion !== null ? trim($this->craftVersion) : '';
            if (preg_match('/^\d+\.\d+/', $core) === 1) {
                $list[] = new InstalledPackage(Ecosystem::Composer, self::CORE_PACKAGE, $core);
            } else {
                $this->warnings[] = 'The Craft version could not be read, so core advisories were not checked.';
            }
        }

        return $list === [] ? null : $list;
    }
}
