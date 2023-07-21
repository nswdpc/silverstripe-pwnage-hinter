<?php

namespace NSWDPC\Pwnage;

use MFlor\Pwned\Exceptions\TooManyRequestsException;
use Symbiote\QueuedJobs\Services\QueuedJobService;
use Symbiote\QueuedJobs\Services\AbstractQueuedJob;
use SilverStripe\Security\Member;
use SilverStripe\Core\Config\Configurable;
use SilverStripe\Core\Injector\Injector;
use SilverStripe\ORM\FieldType\DBDateTime;

/**
 * Check for breached accounts using Member.Email field
 * Set their BreachNotify flag to 1, which is picked up by notification jobs
 * @deprecated this job will be removed in an upcoming release
 */
class BreachedAccountDetectionJob extends AbstractQueuedJob
{
    use Configurable;

    /**
     * @var int
     * Next check interval (days)
     */
    private static $check_in_days = 30;

    /**
     * @var int
     * Batch interval (hours)
     */
    private static $batch_in_hours = 1;

    /**
     * Set whether the check run is fully complete
     */
    protected $runComplete = false;


    public function __construct($limit = null) {
        $this->limit = 10;// default lower limit (req/m -> https://haveibeenpwned.com/API/v3#RateLimiting)
        if(is_numeric($limit)) {
            $this->limit = intval($limit);
        }

    }

    public function addMessage($message, $severity = 'INFO') {
        parent::addMessage($message, $severity);
    }

    /**
     * @return string
     */
    public function getTitle()
    {
        return "Check relevant member accounts for links to data breaches limit:{$this->limit}";
    }

    public function process(): void
    {

        $pwnage = Injector::inst()->create(Pwnage::class);

        if (!Pwnage::config()->get('check_breached_accounts')) {
            throw new \Exception(
                _t(
                    Pwnage::class . ".BREACHED_ACCT_CHECK_NOT_ENABLED",
                    "Breached account check is not enabled"
                )
            );
        }

        if (! ($key = Pwnage::config()->get('hibp_api_key'))) {
            throw new \Exception(
                _t(
                    Pwnage::class . ".NO_HIBP_KEY",
                    "You must provide a HIBP API key to run this job"
                )
            );
        }

        if(!$this->limit) {
            throw new \Exception("This job cannot run, a limit is required in configuration (found limit={$this->limit})");
        }

        // get a list of members with a breach count of zero
        $now = DBDatetime::now();
        $next = DBDatetime::now();

        // Get a list of accounts
        $members = Member::get()->filter('BreachCount', 0)
            ->filterAny([
                'BreachCheckNext:LessThanOrEqual' => $now->Format(DBDatetime::ISO_DATETIME), // now or in the past
                'BreachCheckNext' => null // or never checked
            ]);

        // No records to check ...
        if($members->count() == 0) {
            $this->addMessage("List to check has 0 entries, run complete");
            $this->isComplete = true;
            $this->runComplete = true;
            return;
        }

        // limit the list based on configuration value
        $total = $members->count();
        $members = $members->limit($this->limit);
        $columns = [ "ID", "Email" ];
        $members = $members->setQueriedColumns($columns);

        // Store a value for the next check date
        $nextDays = self::config()->get('check_in_days');
        if($nextDays <= 0 || !is_numeric($nextDays)) {
            // ensure a value
            $nextDays = 30;
        }
        $nextFormatted = $next->modify("+{$nextDays} days")->Format(DBDatetime::ISO_DATETIME);// next check date

        // Process each member
        foreach ($members as $member) {
            $this->currentStep += 1;
            try {
                $member->BreachNotify = 0;// reset
                $member->BreachCheckNext = $nextFormatted;
                // check for a change.. this calls the API
                if ($member->requiresBreachedAccountNotification() ) {
                    $member->BreachNotifyLast = null;
                    $member->BreachNotify = 1;
                }
                $member->write();
            } catch (TooManyRequestsException $e) {
                // Back off a touch, no access to response so retry-after is ?
                $this->addMessage("TooManyRequestsException: backing off");
                sleep(5);
            } catch (ApiException $e) {
                // API client badness
                $this->addMessage("ApiException:" . $e->getMessage());
            } catch (\Exception $e) {
                // general error
                $this->addMessage("Exception:" . $e->getMessage());
            }
        }

        // this batch is complete
        $this->isComplete = true;
        // run is not complete
        $this->runComplete = false;
    }

    public function afterComplete()
    {
        // when to requeue next job
        if($this->runComplete) {
            // next run start
            $requeue_in = self::config()->get('check_in_days');
            if(!$requeue_in || $requeue_in <= 0) {
                $requeue_in = 7;
            }
            $modifier = "+{$requeue_in} days";
        } else {
            // next batch run
            $requeue_in = self::config()->get('batch_in_hours');
            if(!$requeue_in || $requeue_in <= 0) {
                $requeue_in = 1;
            }
            $modifier = "+{$requeue_in} hours";
        }

        $job = new BreachedAccountDetectionJob($this->limit);
        $dt = DBDatetime::now();
        $dt->modify($modifier);
        singleton(QueuedJobService::class)->queueJob($job, $dt->format(DBDatetime::ISO_DATETIME));
    }
}
