<?php

namespace NSWDPC\Pwnage;

use SilverStripe\ORM\DataExtension;
use SilverStripe\Core\Config\Config;
use SilverStripe\Core\Injector\Injector;
use SilverStripe\Forms\ConfirmedPasswordField;
use SilverStripe\Forms\FieldList;
use SilverStripe\Forms\ReadonlyField;
use SilverStripe\Forms\FormField;
use SilverStripe\Security\PasswordValidator;

/**
 * Decorates SilverStripe\Security\Member with fields related to compromised passwords and breaches
 * @property bool $IsPwnedPassword
 * @property bool $PwnedPasswordNotify
 * @extends \SilverStripe\ORM\DataExtension<(\SilverStripe\Security\Member & static)>
 */
class MemberExtension extends DataExtension
{

    private static array $db = [
        'IsPwnedPassword' => 'Boolean',
        'PwnedPasswordNotify' => 'Boolean'// optional flag to notify admin of pwned password
    ];

    private static array $defaults = [
        'IsPwnedPassword' => '0',
        'PwnedPasswordNotify' => '0'
    ];

    private static array $indexes = [
        'IsPwnedPassword' => true,
        'PwnedPasswordNotify' => true
    ];

    /**
     * Show summary fields
     */
    #[\Override]
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

    public function updateCMSFields(FieldList $fields)
    {
        $fields->removeByName([
            'PwnedPasswordNotify'
        ]);

        $confirmed_password_field = $fields->dataFieldByName('Password');
        if ($confirmed_password_field instanceof ConfirmedPasswordField) {
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
