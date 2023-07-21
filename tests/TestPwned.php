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

    public function breaches(): BreachRepository
    {
        $testData = file_get_contents(dirname(__FILE__) . "/data/breach.json");
        $testClientService = new TestClientService();
        $repo = new BreachRepository( $testClientService->getClientWithResponse($testData) );
        return $repo;
    }

    public function pastes(): PasteRepository
    {
        throw new \Exception("Not testing pastes");
    }

    public function passwords(): PasswordRepository
    {
        $testData = file_get_contents(dirname(__FILE__) . "/data/passwords.txt");
        $testClientService = new TestClientService();
        $repo = new PasswordRepository( $testClientService->getClientWithResponse($testData) );
        return $repo;
    }

}
