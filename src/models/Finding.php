<?php

declare(strict_types=1);

namespace ruvelo\securityalerts\models;

/**
 * One advisory that applies to one installed package.
 */
class Finding
{
    /**
     * @param string $package Composer package name
     * @param string $advisoryId Packagist advisory id, e.g. PKSA-xxxx
     * @param string|null $severity As reported by Packagist, sometimes null
     * @param string|null $fixedIn First version that is not affected, when it can be worked out
     * @param bool $exploited Listed in the CISA Known Exploited Vulnerabilities catalogue
     * @param int|null $id Row id, once stored
     * @param string|null $firstSeenAt UTC, once stored
     * @param string|null $fixedAfter When the advisory ends at "<=X" and names no fixed release: X, so the fix is later than that
     */
    public function __construct(
        public readonly string $package,
        public readonly string $installedVersion,
        public readonly string $advisoryId,
        public readonly string $title,
        public readonly ?string $link,
        public readonly ?string $cve,
        public readonly ?string $severity,
        public readonly ?string $fixedIn,
        public readonly bool $exploited = false,
        public readonly ?int $id = null,
        public readonly ?string $firstSeenAt = null,
        public readonly ?string $fixedAfter = null,
    ) {
    }

    public function key(): string
    {
        return $this->package . '|' . $this->advisoryId;
    }

    public function severityLevel(): Severity
    {
        return Severity::fromAdvisory($this->severity);
    }

    public function withExploited(bool $exploited): self
    {
        return new self(
            $this->package,
            $this->installedVersion,
            $this->advisoryId,
            $this->title,
            $this->link,
            $this->cve,
            $this->severity,
            $this->fixedIn,
            $exploited,
            $this->id,
            $this->firstSeenAt,
            $this->fixedAfter,
        );
    }

    /**
     * What to show for the fix: the release, "later than X" when only the last affected version is known, or null.
     */
    public function fixedLabel(): ?string
    {
        if ($this->fixedIn !== null) {
            return $this->fixedIn;
        }

        return $this->fixedAfter !== null ? 'later than ' . $this->fixedAfter : null;
    }

    /**
     * The fix as a phrase for text and email.
     */
    public function fixedPhrase(): string
    {
        return match (true) {
            $this->fixedIn !== null => 'fixed in ' . $this->fixedIn,
            $this->fixedAfter !== null => 'fixed in a release after ' . $this->fixedAfter,
            default => 'no fixed version listed',
        };
    }

    /**
     * Only http(s) links are ever rendered as links.
     */
    public function safeLink(): ?string
    {
        return $this->link !== null && preg_match('#^https?://#i', $this->link) === 1 ? $this->link : null;
    }

    /**
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return [
            'package' => $this->package,
            'installed_version' => $this->installedVersion,
            'advisory_id' => $this->advisoryId,
            'title' => $this->title,
            'link' => $this->link,
            'cve' => $this->cve,
            'severity' => $this->severity,
            'severity_level' => $this->severityLevel()->value,
            'fixed_in' => $this->fixedIn,
            'fixed_after' => $this->fixedAfter,
            'exploited' => $this->exploited,
        ];
    }
}
