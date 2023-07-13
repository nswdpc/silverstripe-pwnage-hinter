<?php

namespace NSWDPC\Pwnage\Tests;

use GuzzleHttp\Client;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Middleware;
use GuzzleHttp\Psr7\Request;
use GuzzleHttp\Psr7\Response;

/**
 * Service class to get a test \GuzzleHttp\Client instance with an optional response
 * Based on \MFlor\Pwned\Tests\Repositories\RepositoryTestCase
 */
class TestClientService
{

    protected array $requestContainer;

    public function getClientWithResponse(string $data = ''): Client
    {
        $mock = new MockHandler([
            new Response(
                200,
                [
                    'Content-Type' => 'application/json'
                ],
                $data
            )
        ]);
        $this->requestContainer = [];
        $history = Middleware::history($this->requestContainer);
        $handler = HandlerStack::create($mock);
        $handler->push($history);
        return new Client([
            'handler' => $handler,
            'headers' => [
            'User-Agent' => 'test-client-service'
            ]
        ]);
    }

}
