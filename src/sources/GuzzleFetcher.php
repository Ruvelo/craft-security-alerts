<?php

declare(strict_types=1);

namespace ruvelo\securityalerts\sources;

use GuzzleHttp\ClientInterface;
use ruvelo\securityalerts\exceptions\SourceException;
use Throwable;

/**
 * Plain HTTPS requests through Craft's own Guzzle client, so proxy settings apply.
 *
 * Nothing is sent but the URL and, for Packagist, the package names.
 */
class GuzzleFetcher implements FetcherInterface
{
    private const TIMEOUT_SECONDS = 20;

    public function __construct(private readonly ClientInterface $client)
    {
    }

    public function get(string $url): string
    {
        return $this->request('GET', $url, []);
    }

    public function postForm(string $url, string $formBody): string
    {
        return $this->request('POST', $url, [
            'body' => $formBody,
            'headers' => ['Content-Type' => 'application/x-www-form-urlencoded'],
        ]);
    }

    /**
     * @param array<string, mixed> $options
     */
    private function request(string $method, string $url, array $options): string
    {
        $options['timeout'] = self::TIMEOUT_SECONDS;
        $options['http_errors'] = false;
        $options['headers'] = ($options['headers'] ?? []) + [
            'User-Agent' => 'Ruvelo-SecurityAlerts/1.0 (+https://github.com/Ruvelo/craft-security-alerts)',
            'Accept' => 'application/json',
        ];

        try {
            $response = $this->client->request($method, $url, $options);
        } catch (Throwable $e) {
            throw new SourceException(sprintf('Could not reach %s: %s', $url, $e->getMessage()), 0, $e);
        }

        if ($response->getStatusCode() !== 200) {
            throw new SourceException(sprintf('%s answered with HTTP %d.', $url, $response->getStatusCode()));
        }

        return (string)$response->getBody();
    }
}
