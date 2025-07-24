<?php

namespace NSWDPC\Pwnage\Tests;

use NSWDPC\Pwnage\Pwnage;
use NSWDPC\Pwnage\PwnedPasswordDigestJob;
use SilverStripe\Core\Config\Configurable;
use SilverStripe\Core\Injector\Injector;
use SilverStripe\Dev\SapphireTest;
use SilverStripe\Security\Member;
use SilverStripe\Security\PasswordValidator;

class PwnageJobTest extends SapphireTest
{
    use Configurable;

    protected $usesDatabase = true;

    protected static $fixture_file = "./PwnageJobTest.yml";

    #[\Override]
    protected function setUp(): void
    {
        // Ensure a validator
        $validator = PasswordValidator::create();
        Member::set_password_validator($validator);

        // Create a local test service
        Injector::inst()->registerService(
            TestPwnage::create(),
            Pwnage::class
        );

        parent::setUp();
    }

    protected function getPwnageInstance(): TestPwnage
    {
        /* @phpstan-ignore return.type */
        return Injector::inst()->create(Pwnage::class);
    }

    public function testPwnedPasswordDigestJob(): void
    {
        $totalMembers = 100;
        $forDigest = 0;
        $notForDigest = 0;
        for ($m = 0;$m < $totalMembers;$m++) {
            $member = Member::create([
                'FirstName' => "First {$m}",
                'Surname' => "Last {$m}",
                'IsPwnedPassword' => random_int(0, 1)
            ]);
            $member->write();
            if ($member->IsPwnedPassword == 1) {
                $forDigest++;
            } else {
                $notForDigest++;
            }
        }

        $job = new PwnedPasswordDigestJob();
        $job->process();

        $to = '';
        $from = null;
        $subject = _t(
            Pwnage::class . ".PWNAGE_DIGEST_SUBJECT",
            "Pwned password digest"
        );

        $warning = _t(
            Pwnage::class . ".NON_ZERO_PWNED_PASSWORDS",
            "There are {member_count} accounts flagged as having a pwned password",
            [
                'member_count' => $forDigest
            ]
        );


        $email = $this->findEmail($to, $from, $subject);

        $this->assertTrue(str_contains((string) $email['PlainContent'], $warning));

    }

}
