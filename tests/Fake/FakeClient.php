<?php

declare(strict_types=1);

namespace ruvelo\securityalerts\tests\Fake;

use GuzzleHttp\Psr7\HttpFactory;
use GuzzleHttp\Psr7\Response;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;
use RuntimeException;

/**
 * A PSR-18 client that never touches the network. It is Packagist, CISA and (when switched on)
 * Valtry's Advisory API, all answering from the fixtures in _files. Valtry's answers are signed with a
 * keypair made per instance, which the scanner under test is told to trust.
 *
 * Like the real ones, Packagist and Valtry only answer for the package names they are asked about.
 */
class FakeClient implements ClientInterface
{
    public const VALTRY_URL = 'https://valtry.test/api/advisories/v1/query';

    /** @var list<string> Every request: "METHOD url body" */
    public array $requests = [];

    public bool $packagistDown = false;

    public bool $kevDown = false;

    /** Whether Valtry answers at all. When false it is "unreachable". */
    public bool $valtryUp = false;

    /** @var int|null Status for every Valtry request, instead of an answer */
    public ?int $valtryStatus = null;

    /** @var bool Serve the advisories under other ids (with the usual ones as aliases), as another source would */
    public bool $valtryRenamesIds = false;

    /** @var (callable(string): string)|null Changes Valtry's body after it is signed */
    public $tamper = null;

    /** @var non-empty-string */
    private string $secretKey;

    private string $publicKey;

    public function __construct()
    {
        $pair = sodium_crypto_sign_keypair();
        $this->secretKey = sodium_crypto_sign_secretkey($pair);
        $this->publicKey = base64_encode(sodium_crypto_sign_publickey($pair));
    }

    /**
     * @return array<string, string>
     */
    public function keys(): array
    {
        return ['test-1' => $this->publicKey];
    }

    /**
     * @return list<string>
     */
    public function to(string $host): array
    {
        return array_values(array_filter($this->requests, static fn(string $r): bool => str_contains($r, $host)));
    }

    public function sendRequest(RequestInterface $request): ResponseInterface
    {
        $url = (string)$request->getUri();
        $body = (string)$request->getBody();
        $this->requests[] = $request->getMethod() . ' ' . $url . ' ' . $body;

        return match (true) {
            str_contains($url, 'packagist.org') => $this->packagist($body),
            str_contains($url, 'cisa.gov') => $this->kevDown ? new Response(503) : $this->json((string)file_get_contents(__DIR__ . '/../_files/kev.json')),
            str_contains($url, 'valtry.test') => $this->valtry($body),
            default => throw new RuntimeException('Unexpected request: ' . $url),
        };
    }

    private function packagist(string $body): ResponseInterface
    {
        if ($this->packagistDown) {
            return new Response(503);
        }
        parse_str($body, $query);
        $asked = is_array($query['packages'] ?? null) ? $query['packages'] : [];

        return $this->json((string)json_encode(['advisories' => array_intersect_key($this->advisories(), array_flip($asked))]));
    }

    private function valtry(string $body): ResponseInterface
    {
        if (!$this->valtryUp) {
            throw new class('Valtry is unreachable') extends RuntimeException implements \Psr\Http\Client\NetworkExceptionInterface {
                public function getRequest(): RequestInterface
                {
                    return (new HttpFactory())->createRequest('POST', FakeClient::VALTRY_URL);
                }
            };
        }
        if ($this->valtryStatus !== null) {
            return new Response($this->valtryStatus);
        }

        $request = json_decode($body, true);
        $request = is_array($request) ? $request : [];
        $kev = $this->kev();
        $advisories = [];
        foreach ($request['packages'] ?? [] as $p) {
            $items = [];
            foreach ($this->advisories()[$p['name']] ?? [] as $a) {
                $cve = $a['cve'] ?? null;
                $entry = $cve !== null ? ($kev[strtoupper($cve)] ?? null) : null;
                $id = $this->valtryRenamesIds ? 'VAL-' . $a['advisoryId'] : $a['advisoryId'];
                $items[] = [
                    'id' => $id, 'source' => 'packagist', 'title' => $a['title'], 'link' => $a['link'], 'cve' => $cve,
                    'aliases' => $this->valtryRenamesIds ? [$a['advisoryId']] : [], 'severity' => $a['severity'] ?? null,
                    'affected' => $a['affectedVersions'], 'fixed_in' => [], 'exploited' => $entry !== null,
                    'kev' => $entry === null ? null : [
                        'cve' => strtoupper($entry['cveID']), 'name' => $entry['vulnerabilityName'],
                        'date_added' => $entry['dateAdded'], 'due_date' => $entry['dueDate'] ?? null, 'ransomware' => false,
                    ],
                    'published_at' => str_replace(' ', 'T', (string)$a['reportedAt']) . 'Z', 'updated_at' => null, 'attribution' => null,
                ];
            }
            $advisories[$p['ecosystem'] . ':' . $p['name']] = $items;
        }

        $json = (string)json_encode([
            'v' => 1, 'nonce' => $request['nonce'] ?? null, 'advisories' => (object)$advisories,
            'stale' => false, 'stale_ecosystems' => [],
        ], JSON_UNESCAPED_SLASHES);
        $signature = 'ed25519=' . base64_encode(sodium_crypto_sign_detached($json, $this->secretKey)) . '; kid=test-1';
        if ($this->tamper !== null) {
            $json = ($this->tamper)($json);
        }

        return $this->json($json)->withHeader('X-Valtry-Signature', $signature);
    }

    /**
     * @return array<string, list<array<string, mixed>>>
     */
    private function advisories(): array
    {
        return json_decode((string)file_get_contents(__DIR__ . '/../_files/advisories.json'), true)['advisories'];
    }

    /**
     * @return array<string, array<string, mixed>>
     */
    private function kev(): array
    {
        $kev = [];
        foreach (json_decode((string)file_get_contents(__DIR__ . '/../_files/kev.json'), true)['vulnerabilities'] as $entry) {
            $kev[strtoupper($entry['cveID'])] = $entry;
        }

        return $kev;
    }

    private function json(string $body): ResponseInterface
    {
        return new Response(200, ['Content-Type' => 'application/json'], $body);
    }
}
