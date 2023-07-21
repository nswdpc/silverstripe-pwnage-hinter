<?php

namespace NSWDPC\Pwnage;

use Silverstripe\ORM\DataExtension;
use SilverStripe\Core\Config\Config;
use SilverStripe\Core\Injector\Injector;
use SilverStripe\Forms\FieldList;
use SilverStripe\Forms\ReadonlyField;
use SilverStripe\Forms\FormField;
use SilverStripe\Security\PasswordValidator;

/**
 * Decorates SilverStripe\Security\Member with fields related to compromised passwords and breaches
 */
class MemberExtension extends DataExtension
{

    /**
     * @var array
     */
    private static $db = [
        'IsPwnedPassword' => 'Boolean',
        'PwnedPasswordNotify' => 'Boolean',// optional flag to notify admin of pwned password
        'BreachCount' => 'Int',
        'BreachNotify' => 'Boolean',// optional flag to notfy admin/user of breached account
        'BreachNotifyLast' => 'Datetime',
        'BreachedSiteHash' => 'Varchar(255)',
        'BreachCheckNext' => 'Datetime'
    ];

    /**
     * @var array
     */
    private static $defaults = [
        'IsPwnedPassword' => '0',
        'PwnedPasswordNotify' => '0',
        'BreachCount' => '0',
        'BreachNotify' => '0',
        'BreachNotifyLast' => null,
        'BreachCheckNext' => null
    ];

    /**
     * @var array
     */
    private static $indexes = [
        'IsPwnedPassword' => true,
        'PwnedPasswordNotify' => true,
        'BreachCount' => true,
        'BreachNotify' => true,
        'BreachCheckNext' => true
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
            . _t(
                    Pwnage::class . '.PASSWORD_MIN_LENGTH',
                    'Minimum length: {min_length} characters',
                    [
                        'min_length' => $min_length
                    ]
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
        if ($this->owner->exists() && $this->owner->isChanged('Email')) {
            $this->owner->BreachCount = 0;
            $this->owner->BreachNotify = 0;
            $this->owner->BreachNotifyLast = null;
            $this->owner->BreachedSiteHash = '';
        }
    }

    /**
     * Test to see whether the member requires a notification
     * @return boolean
     * @throws \Exception
     */
    public function requiresBreachedAccountNotification() {

        try {
            // current hash
            $current_hash = $this->owner->BreachedSiteHash;
            $pwnage = Injector::inst()->create(Pwnage::class);
            if(!is_string($this->owner->Email)) {
                throw new \Exception("Invalid account email");
            }

            $breaches = $pwnage->checkBreachedAccount($this->owner->Email);
            // always store the breach count
            $this->owner->BreachCount = count($breaches);

            // Get the list of breaches by name
            $list = [];
            foreach($breaches as $breach) {
                $list[] = ($breach instanceof \MFlor\Pwned\Models\Breach) ? $breach->getName() : $breach->Name;
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

        } catch (\Exception $e) {
            return false;
        }
    }
}
