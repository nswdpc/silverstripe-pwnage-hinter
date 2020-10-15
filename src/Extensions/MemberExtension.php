<?php

namespace NSWDPC\Pwnage;

use Silverstripe\ORM\DataExtension;
use SilverStripe\Core\Config\Config;
use SilverStripe\Forms\FieldList;
use SilverStripe\Forms\ReadonlyField;
use SilverStripe\Forms\FormField;
use SilverStripe\Security\PasswordValidator;

/**
 * Decorates SilverStripe\Security\Member with fields related to compromised passwords and breaches
 * @author James <james@dpc>
 */
class MemberExtension extends DataExtension
{
    private static $db = [
        'IsPwnedPassword' => 'Boolean',
        'PwnedPasswordNotify' => 'Boolean',// optional flag to notify admin of pwned password
        'BreachCount' => 'Int',
        'BreachNotify' => 'Boolean',// optional flag to notfy admin/user of breached account
        'BreachNotifyLast' => 'Datetime',
        'BreachedSiteHash' => 'Varchar(255)'
    ];

    private static $defaults = [
        'IsPwnedPassword' => '0',
        'PwnedPasswordNotify' => '0',
        'BreachCount' => '0',
        'BreachNotify' => '0',
    ];

    /**
     * Show summary fields
     */
    public function updateSummaryFields(&$fields)
    {
        $fields['IsPwnedPassword'] = _t(
            Pwnage::class . '.PWNED_PASSWORD_DESC_SHORT',
            'Password in breach'
        );
        $fields['BreachCount'] = _t(
            Pwnage::class . '.BREACH_ACCT_DESC_SHORT',
            'Account breach count'
        );
    }

    public function setPasswordValidationInformation(FormField $field)
    {
        $validator = PasswordValidator::create();
        $min_length = $validator->config()->get('min_length');
        $field->setDescription(
            '<div class="alert alert-info">'
            . sprintf(
                _t(
                    Pwnage::class . '.PASSWORD_MIN_LENGTH',
                    'Minimum length: %d characters'
                ),
                $min_length
            )
            . '</div>');
    }

    /**
     * @param FieldList $fields
     */
    public function updateCMSFields(FieldList $fields)
    {
        $fields->removeByName([
            'BreachNotify','PwnedPasswordNotify','BreachedSiteHash'
        ]);

        if ($confirmed_password_field = $fields->dataFieldByName('Password')) {
            $password_field = $confirmed_password_field->getPasswordField();
            if ($password_field) {
                $this->setPasswordValidationInformation($password_field);
            }
        }

        $fields->insertAfter(
            'Password',
            ReadonlyField::create(
                'IsPwnedPassword',
                _t(
                    Pwnage::class . ".PWNED_PASSWORD_DESC",
                    'Whether the password was seen in a breach by HIBP'
                )
            )->setRightTitle(
                _t(
                    Pwnage::class . ".ATTRIBUTION",
                    "We use the 'Have I Been Pwned' service (HIBP) to check whether your password or account has appeared in a data breach. The service is used under the terms of the Creative Commons Attribution 4.0 International License."
                )
            )
        );

        $fields->insertAfter(
            'Email',
            ReadonlyField::create(
                'BreachCount',
                _t(
                    Pwnage::class . ".BREACH_ACCT_DESC",
                    'The number of times the account email address was seen in a breach by HIBP'
                )
            )
        );

        $fields->insertAfter(
            'BreachCount',
            ReadonlyField::create(
                'BreachNotifyLast',
                _t(
                    Pwnage::class . ".BREACH_NOTIFY_LAST",
                    'When the account holder was last notified of a breach'
                )
            )
        );


    }

    public function onBeforeWrite()
    {
        parent::onBeforeWrite();
        if ($this->owner->isChanged('Email')) {
            // when the email address changes, reset the breach values
            $this->owner->BreachCount = 0;
            $this->owner->BreachNotify = 0;
            $this->owner->BreachedSiteHash = '';

            // check for a breached account
            $pwnage = new Pwnage();
            if ($pwnage->config()->get('check_breached_accounts')) {
                try {
                    $count = $pwnage->getBreachedAccountCount($this->owner->Email);
                    $this->owner->BreachCount = $count;
                    if ($count > 0) {
                        /**
                         * the member has changed their email and is in at least one known breach
                         * ...flag for future notification
                         * when requiresBreachedAccountNotification is called
                         * the member will be flagged as requiring a notification
                         * assuming that method return true
                         */
                        $this->owner->BreachNotify = 1;
                    }
                } catch (\Exception $e) {
                    // some badness in the API call
                }
            }
        }
    }

    /**
     * Test to see whether the member requires a notification
     * @return boolean
     * @throws \Exception
     */
    public function requiresBreachedAccountNotification() {
        // current hash
        $current_hash = $this->owner->BreachedSiteHash;
        $breaches = $pwnage->checkBreachedAccount($this->owner->Email);
        if (!is_array($breaches)) {
            // invalid breach result, can't do anything
            throw new \Exception("Invalid breach result");
        }
        $member->BreachCount = count($breaches);
        // sort the list of breaches by name
        $list = [];
        foreach($breaches as $breach) {
            $list[] = $breach->name;
        }

        if(empty($list) && empty($current_hash)) {
            // no change
            return false;
        }

        // create a new hash
        sort($list, SORT_REGULAR);
        $hash = hash("sha256", implode(",", $list));
        $this->owner->BreachedSiteHash = $hash;

        // return if the hashes differ, this means the breach list hash changed
        return $current_hash != $hash;
    }
}
