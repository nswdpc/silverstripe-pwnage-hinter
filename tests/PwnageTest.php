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

    #[\Override]
    protected function setUp(): void
    {

        // Create a local test service
        Injector::inst()->registerService(
            TestPwnage::create(),
            Pwnage::class
        );

        parent::setUp();

        // Register validator
        $validator = Injector::inst()->get( PasswordValidator::class );
        Config::modify()->set( $validator::class, 'min_length', 8);
        $validator->setMinLength(8);
        Member::set_password_validator( $validator );
    }

    protected function getPwnageInstance() : TestPwnage {
        /* @phpstan-ignore return.type */
        return Injector::inst()->create(Pwnage::class);
    }

    public function testPwnedPasswordApiOccurences(): void {
        try {
            $pwnage = $this->getPwnageInstance();
            $errors = [];
            $password = "password";
            $occurences = $pwnage->checkPassword($password);
            $this->assertEquals(10000000, $occurences);
        } catch (ApiException $apiException) {
            $errors[] = $apiException->getMessage();
        }

        $this->assertEmpty($errors, "API exceptions found: " . implode(",", $errors));

    }

    public function testPwnedPasswordApiNoOccurences(): void {

        try {
            $pwnage = $this->getPwnageInstance();
            $errors = [];
            $random_password = bin2hex(random_bytes(64));
            $occurences = $pwnage->checkPassword($random_password);
            $this->assertEquals(0, $occurences);
        } catch (ApiException $apiException) {
            $errors[] = $apiException->getMessage();
        }

        $this->assertEmpty($errors, "API exceptions found: " . implode(",", $errors));

    }

    public function testBreachedAccountApiNoKey(): void {

        try {
            Config::modify()->set(Pwnage::class, 'hibp_api_key', '');
            $pwnage = $this->getPwnageInstance();
            $errors = [];
            // this email address has appeared in a breach
            $email = "test@example.com";
            $occurences = $pwnage->getBreachedAccountCount($email);
        } catch (ApiException $apiException) {
            $errors[] = $apiException->getMessage();
        }

        $this->assertNotEmpty($errors, "API exceptions found: " . implode(",", $errors));

    }

    public function testBreachedAccountWithTestApiKey(): void {

        try {
            Config::modify()->set(Pwnage::class, 'hibp_api_key', 'test-api-key');
            $pwnage = $this->getPwnageInstance();
            $errors = [];
            // this email address has appeared in a breach
            $email = "test@example.com";
            $occurences = $pwnage->getBreachedAccountCount($email);
            $this->assertEquals(2, $occurences);// 2 in test data
        } catch (ApiException $apiException) {
            $errors[] = $apiException->getMessage();
        }

        $this->assertEmpty($errors, "API exceptions found: " . implode(",", $errors));

    }

    /**
     * Test password change with validation error
     */
    public function testMemberChangePasswordInvalid(): void {

        $this->getPwnageInstance();

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
    public function testMemberChangePasswordInvalidAllowed(): void {

        $this->getPwnageInstance();

        $record = [
            'Email' => 'test@example.com',
            'FirstName' => 'Test',
            'Surname' => 'Tester',
        ];
        $member = Member::create($record);
        $member->write();

        // allow
        Pwnage::config()->set('allow_pwned_passwords', true);

        $member->Password = 'password';
        $result = $member->validate();

        $this->assertTrue($result->isValid(), "Password change should be allowed");
        $this->assertEquals(1, $member->IsPwnedPassword);
        $this->assertEquals(1, $member->PwnedPasswordNotify);

    }

    /**
     * Given a member, test email and password changes
     */
    public function testMemberChangePasswordTwice(): void {

        $this->getPwnageInstance();

        $record = [
            'Email' => 'test@example.com',
            'FirstName' => 'Test',
            'Surname' => 'Tester',
        ];
        $member = Member::create($record);
        $member->write();

        // allow
        Pwnage::config()->set('allow_pwned_passwords', true);

        $member->Password = 'password';
        $result = $member->validate();

        $this->assertTrue($result->isValid(), "Password change should be allowed");
        $this->assertEquals(1, $member->IsPwnedPassword, "IsPwnedPassword value");
        $this->assertEquals(1, $member->PwnedPasswordNotify, "PwnedPasswordNotify value");

        $member->Password = 'a-better-password';
        $result = $member->validate();
        $this->assertTrue($result->isValid(), "Password change is OK");
        $this->assertEquals(0, $member->IsPwnedPassword);
        $this->assertEquals(0, $member->PwnedPasswordNotify);

    }

    /**
     * Given a member, test email and password changes
     */
    public function testMemberChangePasswordValid(): void {

        $this->getPwnageInstance();

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
