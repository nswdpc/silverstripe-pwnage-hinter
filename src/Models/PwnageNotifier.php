<?php

namespace NSWDPC\Pwnage;

use SilverStripe\Core\Config\Configurable;
use SilverStripe\Core\Extensible;
use SilverStripe\Control\Email\Email;
use SilverStripe\Security\Group;
use SilverStripe\Security\Member;

/**
 * Model for checking passwords and breaches and the like
 */
class PwnageNotifier
{
    use Configurable;
    use Extensible;

    private static string $font_family = "system-ui, BlinkMacSystemFont, 'Noto Sans', Helvetica, Arial, sans-serif, 'Noto Color Emoji', 'Apple Color Emoji'";

    private static string $email_from = "noreply@localhost";

    private static string $email_from_name = "Account notifier";

    public function sendNotification(
        string $subject,
        string $template,
        array $data = [],
        ?Member $member = null,
        ?Group $group = null
    ): bool {

        $to = $this->getRecipients($member, $group);

        if ($to === []) {
            // no one to send to...
            throw new \Exception("No recipients found for email with template {$template}");
        }

        $email = Email::create();

        $email->setTo($to);

        $email->setHTMLTemplate($template);

        $data['FontFamily'] = self::config()->get('font_family');
        if (!$data['FontFamily']) {
            $data['FontFamily'] = 'sans-serif';
        }

        $email->setData($data);

        $email->setSubject($subject);

        $email->setFrom([
            self::config()->get('email_from') => self::config()->get('email_from_name')
        ]);

        $this->extend('updateNotificationEmail', $email);

        try {
            $email->send();
            $result = true;
            $this->extend('afterNotificationEmail', $email, $result);
            return true;
        } catch (\Exception) {
            $result = false;
            $this->extend('afterNotificationEmail', $email, $result);
            return false;
        }

    }

    /**
     * @return mixed[]
     */
    public function getRecipients(?Member $member = null, ?Group $group = null): array
    {
        $to = [];

        if (!$member instanceof \SilverStripe\Security\Member && !$group instanceof \SilverStripe\Security\Group) {
            // cannot notify
            return [];
        } elseif ($member && !$group instanceof \SilverStripe\Security\Group) {
            if (Email::is_valid_address($member->Email)) {
                $to[$member->Email] = $member->getName();
            }
        } else {
            // group email - each member gets an email
            $members = $group->Members();
            foreach ($members as $member) {
                if (Email::is_valid_address($member->Email)) {
                    $to[$member->Email] = $member->getName();
                }
            }
        }

        return $to;
    }

}
