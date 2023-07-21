<?php

namespace NSWDPC\Pwnage\Tests;

use NSWDPC\Pwnage\Pwnage;
use NSWDPC\Pwnage\ApiException;
use NSWDPC\Pwnage\PwnedPasswordException;
use NSWDPC\Pwnage\PwnedPasswordDigestJob;
use NSWDPC\Pwnage\BreachedAccountDetectionJob;
use NSWDPC\Pwnage\BreachedAccountDigestJob;
use NSWDPC\Pwnage\BreachedAccountNotifyJob;
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


    public function testBreachedAccountDetectionJob() {

        Config::modify()->set( Pwnage::class, 'check_breached_accounts', true );
        Config::modify()->set( Pwnage::class, 'hibp_api_key', 'test-api-key' );
        Config::modify()->set( BreachedAccountDetectionJob::class, 'check_in_days', 10 );

        $nextBatchStartAfter = DBDatetime::now();
        $nextBatchStartAfter->modify("+10 days");

        $members = Member::get()->filter(['BreachCount' => 0]);
        $limit = 5;
        $batches = ceil($members->count() / $limit);

        for($i=0;$i<$batches;$i++) {

            if($i == 0) {
                // kick off the initial job
                $job = new BreachedAccountDetectionJob($limit);
                $job->process();
            }

            $memberList = Member::get()->exclude(['BreachCount' => 0]);
            foreach($memberList as $member) {
                // from test data
                $this->assertEquals(2, $member->BreachCount);
                $this->assertNotNull($member->BreachCheckNext);
                $this->assertEquals(1, $member->BreachNotify);
            }

            // check finished and run after complete
            if($i == 0) {
                // job finished, fire next job creation
                $this->assertTrue($job->jobFinished());
                $job->afterComplete();
            }

            // job descriptor
            $nextJobDescriptor = QueuedJobDescriptor::get()->filter([
                'Implementation' => BreachedAccountDetectionJob::class,
                'JobStatus' => QueuedJob::STATUS_NEW
            ])->first();

            $this->assertInstanceOf(QueuedJobDescriptor::class, $nextJobDescriptor);

            // execute the next job
            $nextJobDescriptor->execute();

        }

        // Verify that batch completed (test expects all)
        $this->assertEquals(0, Member::get()->filter(['BreachCount' => 0])->count());

        $nextJobDescriptor = QueuedJobDescriptor::get()->filter([
            'Implementation' => BreachedAccountDetectionJob::class,
            'JobStatus' => QueuedJob::STATUS_NEW
        ])->first();

        $this->assertInstanceOf(QueuedJobDescriptor::class, $nextJobDescriptor);

        $dt = DBField::create_field(DBDatetime::class, $nextJobDescriptor->StartAfter );
        $this->assertEquals( $nextBatchStartAfter->format( DBDatetime::ISO_DATE ), $dt->format( DBDatetime::ISO_DATE ) );


        // run the digest job
        $job = new BreachedAccountDigestJob();
        $job->process();

        $to = '';
        $from = null;
        $subject = _t(
            Pwnage::class . ".BREACHED_ACCOUNT_DIGEST_SUBJECT",
            "Breached account digest"
        );
        $digestEmail = $this->findEmail($to, $from, $subject);

        $this->assertNotNull( $digestEmail );

        Config::modify()->set( Pwnage::class, 'notify_member_on_breach_detection', true );

        // run the notification job
        $job = new BreachedAccountNotifyJob();
        $job->process();

        $to = '';
        $from = null;
        $subject = _t(
            Pwnage::class . ".YOUR_ACCOUNT_WAS_IN_A_BREACH",
            "Your account was listed in a data breach"
        );
        $notifyEmail = $this->findEmail($to, $from, $subject);

        $this->assertNotNull( $notifyEmail );


    }
}
