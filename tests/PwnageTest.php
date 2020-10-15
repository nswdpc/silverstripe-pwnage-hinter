<?php

namespace NSWDPC\Pwnage;

use MFlor\Pwned\Pwned;
use SilverStripe\Core\Config\Configurable;
use SilverStripe\Control\Email\Email;
use SilverStripe\Dev\SapphireTest;
use SilverStripe\Security\Member;

class PwnageTest extends SapphireTest {

    use Configurable;

    protected $usesDatabase = true;

    private static $pwned_password_list = [
            'password',
            'qwerty123'
    ];

    public function testPwnedPasswordApi() {
        $pwnage = new Pwnage();

        $errors = [];
        foreach($this->config()->get('pwned_password_list') as $password) {
            try {
                $occurences = $pwnage->checkPassword($password);
                $this->assertGreaterThan(0, $occurences, "pwned password '{$password}' returned zero occurrences");
            } catch (ApiException $e) {
                $errors[] = $e->getMessage();
            }
        }

        // generate a long enough password that it won't be pwned
        $random_password = bin2hex(random_bytes(64));
        try {
            $occurences = $pwnage->checkPassword($random_password);
            $this->assertEquals(0, $occurences, "random password '{$random_password}' should have zero occurrences");
        } catch (ApiException $e) {
            $errors[] = $e->getMessage();
        }

        $this->assertEmpty($errors, "API exceptions found: " . implode(",", $errors));

    }

    public function testBreachedAccountApi() {
        $pwnage = new Pwnage();

        if(!$pwnage->config()->get('hibp_api_key')) {
            // don't run test
            return;
        }

        $errors = [];

        // this email address has appeared in a breach
        $email = "test@example.com";

        try {
            $occurences = $pwnage->getBreachedAccountCount($email);
            $this->assertGreaterThan(0, $occurences, "Email '{$email}' returned zero hits");
        } catch (ApiException $e) {
            $errors[] = $e->getMessage();
        }

        $this->assertEmpty($errors, "API exceptions found: " . implode(",", $errors));

    }

    /**
     * Given a member, test email and password changes
     */
    public function testMember() {

        $pwnage = new Pwnage();

        $record = [
            'Email' => 'test@example.com',
            'FirstName' => 'Test',
            'Surname' => 'Tester',
        ];
        $member = Member::create($record);

        $this->assertEquals(0, $member->BreachCount, 'BreachCount should be zero');
        $this->assertEquals(0, $member->BreachNotify, 'BreachNotify should be zero');

        $member->write();

        // can only verify when this is turned on
        if($pwnage->config()->get('check_breached_accounts')) {
            $this->assertGreaterThan(0, $member->BreachCount, 'BreachCount should be > 0');
            $this->assertEquals(1, $member->BreachNotify, 'BreachCount should be > 0');
        }

        $pwned_passwords = $this->config()->get('pwned_password_list');
        $result = $member->changePassword($pwned_passwords[0]);

        $this->assertFalse($result->isValid(), "Password {$pwned_passwords[0]} should be invalid");

        $this->assertEquals(1, $member->IsPwnedPassword, "IsPwnedPassword should be 1");
        $this->assertEquals(1, $member->PwnedPasswordNotify, "PwnedPasswordNotify should be 1");

        $password = bin2hex(random_bytes(32));
        $result = $member->changePassword($password);

        $this->assertTrue($result->isValid(), "Password {$password} should be invalid");

        $this->assertEquals(0, $member->IsPwnedPassword, "IsPwnedPassword should be 0");
        $this->assertEquals(0, $member->PwnedPasswordNotify, "PwnedPasswordNotify should be 0");
    }
}
