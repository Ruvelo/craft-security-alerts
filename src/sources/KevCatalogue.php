<?php

declare(strict_types=1);

namespace ruvelo\securityalerts\sources;

use ruvelo\securityalerts\exceptions\SourceException;

/**
 * The CISA Known Exploited Vulnerabilities catalogue: CVEs with evidence of exploitation in the wild.
 */
class KevCatalogue
{
    public const URL = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';

    public function __construct(private readonly FetcherInterface $fetcher)
    {
    }

    /**
     * @return array<string, true> Upper-case CVE ids, as keys
     * @throws SourceException
     */
    public function exploitedCves(): array
    {
        $data = json_decode($this->fetcher->get(self::URL), true);
        if (!is_array($data) || !isset($data['vulnerabilities']) || !is_array($data['vulnerabilities'])) {
            throw new SourceException('The CISA catalogue is not in the expected format.');
        }

        $cves = [];
        foreach ($data['vulnerabilities'] as $entry) {
            if (is_array($entry) && isset($entry['cveID']) && is_string($entry['cveID'])) {
                $cves[strtoupper(trim($entry['cveID']))] = true;
            }
        }

        return $cves;
    }
}
