<?php

declare(strict_types=1);

namespace ruvelo\securityalerts\tests\Unit\sources;

use GuzzleHttp\Client;
use GuzzleHttp\Exception\ConnectException;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Middleware;
use GuzzleHttp\Psr7\Request;
use GuzzleHttp\Psr7\Response;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\RequestInterface;
use ruvelo\securityalerts\exceptions\SourceException;
use ruvelo\securityalerts\sources\GuzzleFetcher;

class GuzzleFetcherTest extends TestCase
{
    /** @var list<RequestInterface> */
    private array $requests = [];

    /**
     * @param list<Response|\Throwable> $queue
     */
    private function fetcher(array $queue): GuzzleFetcher
    {
        $stack = HandlerStack::create(new MockHandler($queue));
        $stack->push(Middleware::mapRequest(function(RequestInterface $request): RequestInterface {
            $this->requests[] = $request;

            return $request;
        }));

        return new GuzzleFetcher(new Client(['handler' => $stack]));
    }

    public function testGetReturnsTheBody(): void
    {
        $body = $this->fetcher([new Response(200, [], '{"ok":true}')])->get('https://example.com/a');

        $this->assertSame('{"ok":true}', $body);
        $this->assertSame('GET', $this->requests[0]->getMethod());
        $this->assertStringStartsWith('Ruvelo-SecurityAlerts/', $this->requests[0]->getHeaderLine('User-Agent'));
    }

    public function testPostSendsTheFormBodyAndNothingElse(): void
    {
        $this->fetcher([new Response(200, [], '{}')])->postForm('https://example.com/a', 'packages[]=a%2Fb');

        $request = $this->requests[0];
        $this->assertSame('POST', $request->getMethod());
        $this->assertSame('application/x-www-form-urlencoded', $request->getHeaderLine('Content-Type'));
        $this->assertSame('packages[]=a%2Fb', (string)$request->getBody());
        $this->assertFalse($request->hasHeader('Cookie'));
        $this->assertFalse($request->hasHeader('Authorization'));
    }

    public function testANon200IsAnError(): void
    {
        $this->expectException(SourceException::class);
        $this->expectExceptionMessage('HTTP 503');

        $this->fetcher([new Response(503)])->get('https://example.com/a');
    }

    public function testATransportFailureIsAnError(): void
    {
        $this->expectException(SourceException::class);
        $this->expectExceptionMessage('Could not reach');

        $this->fetcher([new ConnectException('timeout', new Request('GET', 'https://example.com/a'))])->get('https://example.com/a');
    }
}
