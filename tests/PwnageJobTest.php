<?php

namespace NSWDPC\Pwnage\Tests;

use NSWDPC\Pwnage\Pwnage;
use NSWDPC\Pwnage\ApiException;
use NSWDPC\Pwnage\PwnedPasswordException;
use NSWDPC\Pwnage\PwnedPasswordDigestJob;
use SilverStripe\Core\Config\Config;
use SilverStripe\Core\Config\Configurable;
use SilverStripe\Core\Injector\Injector;
use SilverStripe\Control\Email\Email;
use SilverStripe\Dev\SapphireTest;
use SilverStripe\ORM\FieldType\DBField;
use SilverStripe\ORM\FieldType\DBDate;
use SilverStripe\ORM\FieldType\DBDateTime;
use SilverStripe\Security\Member;
use SilverStripe\Security\PasswordValidator;
use Symbiote\QueuedJobs\DataObjects\QueuedJobDescriptor;
use Symbiote\QueuedJobs\Services\QueuedJob;

class PwnageJobTest extends SapphireTest {

    use Configurable;

    protected $usesDatabase = true;

    protected static $fixture_file = "./PwnageJobTest.yml";

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

    public function testPwnedPasswordDigestJob() {
        $totalMembers = 100;
        $members = [];
        $forDigest = $notForDigest = 0;
        for($m=0;$m<$totalMembers;$m++) {
            $member = Member::create([
                'FirstName' => "First {$m}",
                'Surname' => "Last {$m}",
                'IsPwnedPassword' => rand(0,1)
            ]);
            $member->write();
            if($member->IsPwnedPassword == 1) {
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

        $this->assertNotNull( strpos($email['PlainContent'], $warning) !== false );

    }

}
