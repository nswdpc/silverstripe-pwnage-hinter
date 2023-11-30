<?php

namespace NSWDPC\Pwnage;

use Symbiote\QueuedJobs\Services\QueuedJobService;
use Symbiote\QueuedJobs\Services\AbstractQueuedJob;
use SilverStripe\Security\Member;
use SilverStripe\Core\Config\Configurable;
use SilverStripe\Core\Injector\Injector;
use SilverStripe\ORM\FieldType\DBField;
use SilverStripe\ORM\FieldType\DBDatetime;
use SilverStripe\View\ArrayData;

/**
 * Notify group(s) with pwned password count, not specific information
 */
class PwnedPasswordDigestJob extends AbstractQueuedJob
{
    use Configurable;

    /**
     * Requeue job in (seconds)
     */
    private static $requeue_in = 86400;

    /**
     * @return string
     */
    public function getTitle()
    {
        return "Pwned password digest";
    }

    public function process(): void
    {

        $pwnage = Injector::inst()->create(Pwnage::class);

        if(!Pwnage::config()->get('notify_pwned_password_digest')) {
            // turned off
            $this->addMessage("Not sending, notify_pwned_password_digest is off");
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

        // get a list of members with a pwned password count not zero
        $members = Member::get()->exclude('IsPwnedPassword', 0);

        $notifier = new PwnageNotifier();

        $member_count = $members->count();

        $subject = _t(
            Pwnage::class . ".PWNAGE_DIGEST_SUBJECT",
            "Pwned password digest"
        );

        $warning = "";
        if($member_count > 0) {
            $warning = _t(
                Pwnage::class . ".NON_ZERO_PWNED_PASSWORDS",
                "There are {member_count} accounts flagged as having a pwned password",
                [
                    'member_count' => $member_count
                ]
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
                            ])->renderWith('NSWDPC/Pwnage/PasswordDigestContent')
            ),
            'Footer' => strip_tags(
                            _t(
                                Pwnage::class . ".ATTRIBUTION",
                                "We use the 'Have I Been Pwned' service to check whether"
                                . " your password has appeared in a data breach"
                                . " under the terms of the Creative Commons Attribution 4.0"
                                . " International License."
                            )
            )
        ];

        foreach($groups as $group) {
            $this->currentStep += 1;
            $this->addMessage("Sending digest to group {$group->Title}");
            $notifier->sendNotification(
                $subject,
                "NSWDPC/Pwnage/PwnedPasswordDigest",
                $data,
                null,
                $group
            );
        }

        $this->isComplete = true;

    }

    public function afterComplete()
    {
        $requeue_in = self::config()->get('requeue_in');
        if(!$requeue_in || $requeue_in <= 0) {
            return null;
        }
        $job = new PwnedPasswordDigestJob();
        $dt = new \DateTime();
        $dt->modify("+{$requeue_in} seconds");
        singleton(QueuedJobService::class)->queueJob($job, $dt->format('Y-m-d H:i:s'));
    }
}
