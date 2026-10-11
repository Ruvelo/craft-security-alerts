<?php

declare(strict_types=1);

namespace ruvelo\securityalerts\services;

use Composer\Semver\Comparator;
use Composer\Semver\Semver;
use Throwable;

/**
 * Decides whether an advisory's affected-version constraint covers an installed version,
 * and works out which version fixes it.
 */
class AdvisoryMatcher
{
    private const MAX_HOPS = 10;

    /**
     * @param string $constraint e.g. ">=5.0.0-RC1,<5.6.17|>=4.0.0-RC1,<4.14.13"
     * @return bool False when the version or constraint cannot be understood (a dev branch, say)
     */
    public function affects(string $installedVersion, string $constraint): bool
    {
        try {
            return Semver::satisfies($installedVersion, $constraint);
        } catch (Throwable) {
            return false;
        }
    }

    /**
     * The nearest version above the installed one that no branch of the constraint covers.
     *
     * Advisories list one range per release line, so "<4.14.13" alone is not a fix for a site
     * on 4.x. This walks up the upper bounds until it lands outside the constraint.
     *
     * @return string|null Null when the constraint has no upper bound that could be followed
     */
    public function fixedIn(string $installedVersion, string $constraint): ?string
    {
        $version = $installedVersion;
        for ($hop = 0; $hop < self::MAX_HOPS; $hop++) {
            $upper = $this->upperBoundOfMatchingBranch($version, $constraint);
            if ($upper === null) {
                return null;
            }
            if (!$this->affects($upper, $constraint)) {
                return $upper;
            }
            $version = $upper;
        }

        return null;
    }

    /**
     * Many advisories end a range with "<=5.6.16" rather than "<5.6.17", because the fixed
     * release is not in the data. The fix is then known only to be later than that version.
     *
     * @return string|null The lowest "<=" bound among the branches that cover the installed version
     */
    public function fixedAfter(string $installedVersion, string $constraint): ?string
    {
        $lowest = null;
        foreach (preg_split('/\s*\|\|?\s*/', trim($constraint)) ?: [] as $branch) {
            if ($branch === '' || !$this->affects($installedVersion, $branch)) {
                continue;
            }
            if (preg_match('/(?:^|[\s,])<=\s*([^\s,|<>=]+)/', $branch, $m) !== 1) {
                continue;
            }
            if ($lowest === null || $this->isLower($m[1], $lowest)) {
                $lowest = $m[1];
            }
        }

        return $lowest;
    }

    private function upperBoundOfMatchingBranch(string $version, string $constraint): ?string
    {
        $lowest = null;
        foreach (preg_split('/\s*\|\|?\s*/', trim($constraint)) ?: [] as $branch) {
            if ($branch === '' || !$this->affects($version, $branch)) {
                continue;
            }
            if (preg_match('/(?:^|[\s,])<(?!=)\s*([^\s,|<>=]+)/', $branch, $m) !== 1) {
                continue;
            }
            if ($lowest === null || $this->isLower($m[1], $lowest)) {
                $lowest = $m[1];
            }
        }

        return $lowest;
    }

    private function isLower(string $a, string $b): bool
    {
        try {
            return Comparator::lessThan($a, $b);
        } catch (Throwable) {
            return false;
        }
    }
}
