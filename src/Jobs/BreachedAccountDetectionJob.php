<?php

namespace NSWDPC\Pwnage;

use Symbiote\QueuedJobs\Services\QueuedJobService;
use Symbiote\QueuedJobs\Services\AbstractQueuedJob;
use SilverStripe\Security\Member;
use SilverStripe\Core\Config\Configurable;
use SilverStripe\Core\Injector\Injector;

/**
 * Check for breached accounts using Member.Email field
 * Set their BreachNotify flag to 1, which is picked up by notification jobs
 */
class BreachedAccountDetectionJob extends AbstractQueuedJob
{
    use Configurable;

    const MIN_SLEEP = 1500;//https://haveibeenpwned.com/API/v3#RateLimiting

    private static $sleep_time = 2000;//ms

    /**
     * @return string
     */
    public function getTitle()
    {
        return "Check relevant member accounts for links to data breaches";
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

        // get a list of members with a breach count of zero
        $members = Member::get()->filter('BreachCount', 0);
        $columns = [ "ID", "Email" ];
        $members->setQueriedColumns($columns);

        $sleep_time = self::config()->get('sleep_time');
        if ($sleep_time < self::MIN_SLEEP) {
            // reset to min sleep value
            $sleep_time = MIN_SLEEP;
        }

        foreach ($members as $member) {
            try {
                $member->BreachNotify = 0;//reset
                // check for a change.. this calls the API
                $requires_notification = $member->requiresBreachedAccountNotification();
                /**
                 * flag for notification iif required
                 */
                if ($requires_notification) {
                    $member->BreachNotify = 1;
                }
                $member->write();
            } catch (ApiException $e) {
                // API badness
            } catch (\Exception $e) {
                // general error
            }
            // sleep to keep below rate limiting
            sleep($sleep_time);
        }
    }

    public function afterComplete()
    {
        $job = new BreachedAccountDetectionJob();
        $dt = new \DateTime();
        $dt->modify('+1 day');
        singleton(QueuedJobService::class)->queueJob($job, $dt->format('Y-m-d H:i:s'));
    }
}
