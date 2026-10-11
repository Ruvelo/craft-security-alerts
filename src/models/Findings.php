<?php

declare(strict_types=1);

namespace ruvelo\securityalerts\models;

/**
 * Helpers for lists of findings.
 */
class Findings
{
    /**
     * Exploited first, then the most severe, then by package name.
     *
     * @param list<Finding> $findings
     * @return list<Finding>
     */
    public static function sorted(array $findings): array
    {
        usort(
            $findings,
            static fn(Finding $a, Finding $b): int => ($b->exploited <=> $a->exploited)
                ?: ($b->severityLevel()->rank() <=> $a->severityLevel()->rank())
                ?: ($a->package <=> $b->package)
                ?: ($a->advisoryId <=> $b->advisoryId),
        );

        return $findings;
    }

    /**
     * @param list<Finding> $findings
     */
    public static function exploitedCount(array $findings): int
    {
        return count(array_filter($findings, static fn(Finding $f): bool => $f->exploited));
    }
}
