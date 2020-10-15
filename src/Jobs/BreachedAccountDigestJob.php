<?php

namespace NSWDPC\Pwnage;

use Symbiote\QueuedJobs\Services\QueuedJobService;
use Symbiote\QueuedJobs\Services\AbstractQueuedJob;
use SilverStripe\Security\Member;
use SilverStripe\Core\Config\Configurable;
use SilverStripe\ORM\FieldType\DBField;
use SilverStripe\ORM\FieldType\DBDatetime;
use SilverStripe\View\ArrayData;

/**
 * Notify group(s) of breached account count
 * @author James <james@dpc>
 */
class BreachedAccountDigestJob extends AbstractQueuedJob
{
    use Configurable;

    private static $requeue_in = 86400;

    /**
     * @return string
     */
    public function getTitle()
    {
        return "Breached account digest";
    }

    public function process(): void
    {

        $pwnage = new Pwnage();

        if(!$pwnage->config()->get('notify_breach_account_digest')) {
            // turned off
            $this->addMessage("Not sending, notify_breach_account_digest is off");
            $this->isComplete = true;
            return;
        }

        // by default this gets groups with the 'ADMIN' permission
        $groups = $pwnage->getDigestNotificationGroups();

        if(!$groups || $groups->count() == 0) {
            // no groups to notify
            $this->addMessage("Not sending, no groups to notify - is the permission code configured?");
            $this->isComplete = true;
            return;
        }

        // get a list of members with a breach count not zero
        $members = Member::get()->exclude('BreachCount', 0);

        $notifier = new PwnageNotifier();

        $member_count = $members->count();

        $subject = sprintf(
            _t(
                Pwnage::class . ".BREACHED_ACCOUNT_DIGEST_SUBJECT",
                "Breached account digest: there are %d accounts flagged"
            ), $member_count
        );

        $warning = "";
        if($member_count > 0) {
            $warning = sprintf(
                _t(
                    Pwnage::class . ".NON_ZERO_BREACHED_ACCOUNTS",
                    "There are %d accounts flagged as appearing in known data breaches"
                ), $member_count
            );
        }

        $content_data = ArrayData::create();

        $data = [
            'Title' => $subject,
            'Warning' => $warning,
            'Content' => DBField::create_field(
                            'HTMLText',
                            $content_data->customise([
                                'MemberCount' => $member_count
                            ])->renderWith('NSWDPC/Pwnage/BreachDigestContent')
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

        foreach($groups as $group) {
            $this->addMessage("Sending digest to group {$group->Title}");
            $notifier->sendNotification(
                $subject,
                "NSWDPC/Pwnage/BreachedAccountDigest",
                $data,
                null,
                $group
            );
        }

        $this->isComplete = true;

    }

    public function afterComplete()
    {
        $requeue_in = $this->config()->get('requeue_in');
        if(!$requeue_in || $requeue_in <= 0) {
            return null;
        }
        $job = new BreachedAccountDigestJob();
        $dt = new \DateTime();
        $dt->modify("+{$requeue_in} seconds");
        singleton(QueuedJobService::class)->queueJob($job, $dt->format('Y-m-d H:i:s'));
    }
}
