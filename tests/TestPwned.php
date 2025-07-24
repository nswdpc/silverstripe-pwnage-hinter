<?php

namespace NSWDPC\Pwnage\Tests;

use MFlor\Pwned\Pwned;
use MFlor\Pwned\Repositories\PasswordRepository;
use MFlor\Pwned\Repositories\BreachRepository;
use MFlor\Pwned\Repositories\PasteRepository;

/**
 * Test client for Pwned
 */
class TestPwned extends Pwned
{
    #[\Override]
    public function breaches(): BreachRepository
    {
        $testData = file_get_contents(__DIR__ . "/data/breach.json");
        $testClientService = new TestClientService();
        return new BreachRepository($testClientService->getClientWithResponse($testData));
    }

    #[\Override]
    public function pastes(): PasteRepository
    {
        throw new \Exception("Not testing pastes");
    }

    #[\Override]
    public function passwords(): PasswordRepository
    {
        $testData = file_get_contents(__DIR__ . "/data/passwords.txt");
        $testClientService = new TestClientService();
        return new PasswordRepository($testClientService->getClientWithResponse($testData));
    }

}
