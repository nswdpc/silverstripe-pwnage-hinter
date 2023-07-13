<?php

namespace NSWDPC\Pwnage\Tests;

use NSWDPC\Pwnage\Pwnage;

/**
 * Test class
 */
class TestPwnage extends Pwnage
{
    /**
     * Return the Pwned API client
     */
    protected function getClient($api_key = null) : TestPwned {
        return new TestPwned($api_key);
    }
}
