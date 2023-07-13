<?php

namespace NSWDPC\Pwnage\Tests;

use NSWDPC\Pwnage\Pwnage;
use NSWDPC\Pwnage\ApiException;
use NSWDPC\Pwnage\PwnedPasswordException;
use SilverStripe\Core\Config\Config;
use SilverStripe\Core\Config\Configurable;
use SilverStripe\Core\Injector\Injector;
use SilverStripe\Control\Email\Email;
use SilverStripe\Dev\SapphireTest;
use SilverStripe\Security\Member;
use SilverStripe\Security\PasswordValidator;

class PwnageTest extends SapphireTest {

    use Configurable;

    protected $usesDatabase = true;

    protected function setUp(): void
    {
        // Ensure a validator
        $validator = PasswordValidator::create();
        Member::set_password_validator( $validator );

        // Create a local test service
        Injector::inst()->registerService(
            new TestPwnage(),
            Pwnage::class
        );

        parent::setUp();
    }

    protected function getPwnageInstance() : TestPwnage {
        $pwnage = Injector::inst()->create(Pwnage::class);
        return $pwnage;
    }

    public function testPwnedPasswordApiOccurences() {
        try {
            $pwnage = $this->getPwnageInstance();
            $errors = [];
            $password = "password";
            $occurences = $pwnage->checkPassword($password);
            $this->assertEquals(10000000, $occurences);
        } catch (ApiException $e) {
            $errors[] = $e->getMessage();
        }

        $this->assertEmpty($errors, "API exceptions found: " . implode(",", $errors));

    }

    public function testPwnedPasswordApiNoOccurences() {

        try {
            $pwnage = $this->getPwnageInstance();
            $errors = [];
            $random_password = bin2hex(random_bytes(64));
            $occurences = $pwnage->checkPassword($random_password);
            $this->assertEquals(0, $occurences);
        } catch (ApiException $e) {
            $errors[] = $e->getMessage();
        }

        $this->assertEmpty($errors, "API exceptions found: " . implode(",", $errors));

    }

    public function testBreachedAccountApiNoKey() {

        try {
            $pwnage = $this->getPwnageInstance();
            $errors = [];
            // this email address has appeared in a breach
            $email = "test@example.com";
            $occurences = $pwnage->getBreachedAccountCount($email);
        } catch (ApiException $e) {
            $errors[] = $e->getMessage();
        }

        $this->assertNotEmpty($errors, "API exceptions found: " . implode(",", $errors));

    }

    public function testBreachedAccountWithTestApiKey() {

        try {
            Config::modify()->set(Pwnage::class, 'hibp_api_key', 'test-api-key');
            $pwnage = $this->getPwnageInstance();
            $errors = [];
            // this email address has appeared in a breach
            $email = "test@example.com";
            $occurences = $pwnage->getBreachedAccountCount($email);
            $this->assertEquals(2, $occurences);// 2 in test data
        } catch (ApiException $e) {
            $errors[] = $e->getMessage();
        }

        $this->assertEmpty($errors, "API exceptions found: " . implode(",", $errors));

    }

    /**
     * Test password change with validation error
     */
    public function testMemberChangePasswordInvalid() {

        $pwnage = $this->getPwnageInstance();

        $record = [
            'Email' => 'test@example.com',
            'FirstName' => 'Test',
            'Surname' => 'Tester',
        ];
        $member = Member::create($record);
        $member->write();

        // block
        Pwnage::config()->set('allow_pwned_passwords', false);

        $result = $member->changePassword('password');

        $this->assertFalse($result->isValid(), "Password change should be invalid");
        $this->assertEquals(0, $member->IsPwnedPassword);
        $this->assertEquals(0, $member->PwnedPasswordNotify);

    }

    /**
     * Test password change with warning flag
     */
    public function testMemberChangePasswordInvalidAllowed() {

        $pwnage = $this->getPwnageInstance();

        $record = [
            'Email' => 'test@example.com',
            'FirstName' => 'Test',
            'Surname' => 'Tester',
        ];
        $member = Member::create($record);
        $member->write();

        // allow
        Pwnage::config()->set('allow_pwned_passwords', true);

        $result = $member->changePassword('password');

        $this->assertTrue($result->isValid(), "Password change should be allowed");
        $this->assertEquals(1, $member->IsPwnedPassword);
        $this->assertEquals(1, $member->PwnedPasswordNotify);

    }

    /**
     * Given a member, test email and password changes
     */
    public function testMemberChangePasswordTwice() {

        $pwnage = $this->getPwnageInstance();

        $record = [
            'Email' => 'test@example.com',
            'FirstName' => 'Test',
            'Surname' => 'Tester',
        ];
        $member = Member::create($record);
        $member->write();

        // allow
        Pwnage::config()->set('allow_pwned_passwords', true);

        $result = $member->changePassword('password');

        $this->assertTrue($result->isValid(), "Password change should be allowed");
        $this->assertEquals(1, $member->IsPwnedPassword, "IsPwnedPassword value");
        $this->assertEquals(1, $member->PwnedPasswordNotify, "PwnedPasswordNotify value");

        $result = $member->changePassword('a-better-password');
        $this->assertTrue($result->isValid(), "Password change is OK");
        $this->assertEquals(0, $member->IsPwnedPassword);
        $this->assertEquals(0, $member->PwnedPasswordNotify);

    }

    /**
     * Given a member, test email and password changes
     */
    public function testMemberChangePasswordValid() {

        $pwnage = $this->getPwnageInstance();

        $record = [
            'Email' => 'test@example.com',
            'FirstName' => 'Test',
            'Surname' => 'Tester',
        ];
        $member = Member::create($record);
        $member->write();

        $password = bin2hex(random_bytes(32));
        $result = $member->changePassword($password);

        $this->assertTrue($result->isValid(), "Password should be valid");

        $this->assertEquals(0, $member->IsPwnedPassword, "IsPwnedPassword should be 0");
        $this->assertEquals(0, $member->PwnedPasswordNotify, "PwnedPasswordNotify should be 0");
    }
}
