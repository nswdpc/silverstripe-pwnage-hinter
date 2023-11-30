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
        'PwnedPasswordNotify' => 'Boolean'// optional flag to notify admin of pwned password
    ];

    /**
     * @var array
     */
    private static $defaults = [
        'IsPwnedPassword' => '0',
        'PwnedPasswordNotify' => '0'
    ];

    /**
     * @var array
     */
    private static $indexes = [
        'IsPwnedPassword' => true,
        'PwnedPasswordNotify' => true
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
    }

    public function setPasswordValidationInformation(FormField $field)
    {
        $validator = Injector::inst()->get(PasswordValidator::class);
        $min_length = $validator->getMinLength();
        $field->setDescription(_t(
            Pwnage::class . '.PASSWORD_MIN_LENGTH',
            'Minimum length: {min_length} characters',
            [
                'min_length' => $min_length
            ]
        ));
    }

    /**
     * @param FieldList $fields
     */
    public function updateCMSFields(FieldList $fields)
    {
        $fields->removeByName([
            'PwnedPasswordNotify'
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
                    "We use the 'Have I Been Pwned' service (HIBP) to check whether your password has appeared in a data breach. The service is used under the terms of the Creative Commons Attribution 4.0 International License."
                )
            )
        );

    }

}
