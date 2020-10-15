<?php

namespace NSWDPC\Pwnage;

use SilverStripe\Core\Config\Configurable;
use SilverStripe\Core\Extensible;
use SilverStripe\Control\Email\Email;
use SilverStripe\Security\Group;
use SilverStripe\Security\Member;

/**
 * Model for checking passwords and breaches and the like
 * @author James <james.ellis@dpc.nsw.gov.au>
 */
class PwnageNotifier
{

    use Configurable;
    use Extensible;

    private static $font_family = "system-ui, BlinkMacSystemFont, 'Noto Sans', Helvetica, Arial, sans-serif, 'Noto Color Emoji', 'Apple Color Emoji'";

    private static $email_from = "noreply@localhost";
    private static $email_from_name = "Account notifier";

    public function sendNotification(
        $subject,
        $template,
        $data = [],
        Member $member = null,
        Group $group = null
    ) {

        $to = $this->getRecipients($member, $group);

        if(empty($to)) {
            // no one to send to...
            throw new \Exception("No recipients found for email with template {$template}");
        }

        $email = Email::create();

        $email->setTo($to);

        $email->setHTMLTemplate($template);

        $data['FontFamily'] = $this->config()->get('font_family');
        if(!$data['FontFamily']) {
            $data['FontFamily'] = 'sans-serif';
        }

        $email->setData($data);

        $email->setSubject($subject);

        $email->setFrom([
            $this->config()->get('email_from') => $this->config()->get('email_from_name')
        ]);

        $this->extend('updateNotificationEmail', $email);

        $result = $email->send();

        $this->extend('afterNotificationEmail', $email, $result);

        return $result;

    }

    public function getRecipients(Member $member = null, Group $group = null) {
        $to = [];

        if(!$member && !$group) {
            // cannot notify
            return [];
        } else if($member && !$group) {
            if(Email::is_valid_address($member->Email)) {
                $to[$member->Email] = $member->getName();
            }
        } else {
            // group email - each member gets an email
            $members = $group->Members();
            foreach($members as $member) {
                if(Email::is_valid_address($member->Email)) {
                    $to[$member->Email] = $member->getName();
                }
            }
        }

        return $to;
    }

}
