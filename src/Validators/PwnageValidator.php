<?php

namespace NSWDPC\Pwnage;

use SilverStripe\Security\PasswordValidator;
use SilverStripe\Core\Injector\Injector;
use SilverStripe\ORM\ValidationResult;
use SilverStripe\Security\Member;
use SilverStripe\Core\Config\Config;
use SilverStripe\Core\Extension;

/**
 * Extends {@link SilverStripe\Security\PasswordValidator} to provide pwnage smarts
 * @author James <james@dpc>
 */
class PwnageValidator extends Extension
{

    /**
     * Validate the password against the Pwmnage providers configured and set values on the Member record
     * @param string $password
     * @param Member $member
     * @param ValidationResult $validation_result
     * @param PasswordValidator $validator
     * @return void
     * @todo log an error on service/api/network failure ?
     */
    public function updateValidatePassword($password, $member, ValidationResult $validation_result, PasswordValidator $validator)
    {
        if (!$validation_result->isValid()) {
            // no need to continue with validation here as the password is already invalid for some reason
            return;
        }
        if (Config::inst()->get(Pwnage::class, 'check_pwned_passwords')) {
            try {
                $pwnage = new Pwnage();
                $occurences = $pwnage->checkPassword($password);
                if ($occurences > 0) {
                    if (!$pwnage->config()->get('allow_pwned_passwords')) {
                        // password will not be changed
                        $member->IsPwnedPassword = 0;
                        $member->PwnedPasswordNotify = 0;

                        // not allowing pwned passwords
                        $error = _t(
                            Pwnage::class . ".PASSWORD_PWNED_BLOCKED",
                            'The password provided has appeared in at least one data breach and cannot be used on this website. Please change your password and try again.'
                        );

                        // fail the validation process
                        $validation_result->addError($error, ValidationResult::TYPE_ERROR, 'PWNED_PASSWORD');
                    } else {

                        // password is allowed, with warning, also flag the account

                        $member->IsPwnedPassword = 1;//store that is (will save if allowed)
                        $member->PwnedPasswordNotify = 1;//flag for notification

                        $error = _t(
                            Pwnage::class . ".PASSWORD_PWNED_WARNING",
                            'The password provided has appeared in at least one data breach. Please change your password immediately.'
                        );
                        $validation_result->addMessage($error, ValidationResult::TYPE_WARNING, 'PWNED_PASSWORD');
                    }
                } else {
                    // reset to zero
                    $member->IsPwnedPassword = 0;
                    $member->PwnedPasswordNotify = 0;
                }
            } catch (\Exception $e) {
                // log an error ?
            }
        }
    }
}
