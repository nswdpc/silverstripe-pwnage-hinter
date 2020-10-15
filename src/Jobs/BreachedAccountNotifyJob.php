<?php

namespace NSWDPC\Pwnage;

use Symbiote\QueuedJobs\Services\QueuedJobService;
use Symbiote\QueuedJobs\Services\AbstractQueuedJob;
use SilverStripe\Security\Member;
use SilverStripe\Core\Config\Configurable;
use SilverStripe\ORM\FieldType\DBField;
use SilverStripe\ORM\FieldType\DBDatetime;

/**
 * Notify accounts that have the breached flag
 * Requires notify_member_on_breach_detection to be true
 * @author James <james@dpc>
 */
class BreachedAccountNotifyJob extends AbstractQueuedJob
{
    use Configurable;

    private static $requeue_in = 86400;

    /**
     * @return string
     */
    public function getTitle()
    {
        return "Notify member accounts that have at least one breach count";
    }

    public function process(): void
    {
        $pwnage = new Pwnage();

        if(!$pwnage->config()->get('notify_member_on_breach_detection')) {
            $this->addMessage('Member notification is turned off');
            $this->isComplete = true;
            return;
        }

        // get a list of members with a breach count not zero
        $members = Member::get()
                    ->exclude('BreachCount', 0)
                    // and are flagged for notification
                    ->filter('BreachNotify', 1);

        $notifier = new PwnageNotifier();

        foreach ($members as $member) {

            $subject = _t(
                Pwnage::class . ".YOUR_ACCOUNT_WAS_IN_A_BREACH",
                "Your account was listed in a data breach"
            );

            $data = [
                'Title' => $subject,
                'Warning' => 'Warning: Your account was listed in a data breach',
                'Content' => DBField::create_field(
                                'HTMLText',
                                $member->renderWith('NSWDPC/Pwnage/MemberBreach')
                ),
                'Footer' => strip_tags(
                                _t(
                                    Pwnage::class . ".ATTRIBUTION",
                                    "We use the 'Have I Been Pwned' service to check whether"
                                    . " your password or account has appeared in a data breach"
                                    . " under the terms of the Creative Commons Attribution 4.0"
                                    . " International License."
                                )
                )
            ];

            $notifier->sendNotification(
                $subject,
                "NSWDPC/Pwnage/BreachedAccountNotification",
                $data,
                $member
            );

            $member->BreachNotify = 0;
            $member->BreachNotifyLast = DBDatetime::now();
            $member->write();

        }
    }

    public function afterComplete()
    {
        $requeue_in = $this->config()->get('requeue_in');
        if(!$requeue_in || $requeue_in <= 0) {
            return null;
        }
        $job = new BreachedAccountNotifyJob();
        $dt = new \DateTime();
        $dt->modify("+{$requeue_in} seconds");
        singleton(QueuedJobService::class)->queueJob($job, $dt->format('Y-m-d H:i:s'));
    }
}
