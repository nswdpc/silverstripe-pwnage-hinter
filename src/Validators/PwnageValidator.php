<?php

namespace NSWDPC\Pwnage;

use SilverStripe\Security\Validation\PasswordValidator;
use SilverStripe\Core\Injector\Injector;
use SilverStripe\Security\Member;
use SilverStripe\Core\Extension;

/**
 * Extends {@link \SilverStripe\Security\Validation\PasswordValidator} to provide pwnage smarts
 * @extends \SilverStripe\Core\Extension<static>
 */
class PwnageValidator extends Extension
{
    /**
     * Validate the password against the Pwnage providers configured and set values on the Member record
     * @param Member $member
     * @return void
     * @todo log an error on service/api/network failure ?
     */
    public function updateValidatePassword(string $password, $member, \SilverStripe\Core\Validation\ValidationResult $validationResult, PasswordValidator $validator)
    {

        if (!$validationResult->isValid()) {
            // no need to continue with validation here as the password is already invalid for some reason
            return;
        }

        if (Pwnage::config()->get('check_pwned_passwords')) {
            try {
                $pwnage = Injector::inst()->create(Pwnage::class);
                $occurences = $pwnage->checkPassword($password);
                if ($occurences > 0) {
                    if (!Pwnage::config()->get('allow_pwned_passwords')) {
                        // password will not be changed
                        $member->IsPwnedPassword = 0;
                        $member->PwnedPasswordNotify = 0;

                        // not allowing pwned passwords
                        $error = _t(
                            Pwnage::class . ".PASSWORD_PWNED_BLOCKED",
                            'The password provided has appeared in at least one data breach and cannot be used on this website. Please change your password and try again.'
                        );

                        // fail the validation process
                        $validationResult->addError($error, \SilverStripe\Core\Validation\ValidationResult::TYPE_ERROR, 'PWNED_PASSWORD');
                    } else {

                        // password is allowed, with warning, also flag the account

                        $member->IsPwnedPassword = 1;//store that is (will save if allowed)
                        $member->PwnedPasswordNotify = 1;//flag for notification

                        $error = _t(
                            Pwnage::class . ".PASSWORD_PWNED_WARNING",
                            'The password provided has appeared in at least one data breach. Please change your password immediately.'
                        );
                        $validationResult->addMessage($error, \SilverStripe\Core\Validation\ValidationResult::TYPE_WARNING, 'PWNED_PASSWORD_WARNING');
                    }
                } else {
                    // reset to zero
                    $member->IsPwnedPassword = 0;
                    $member->PwnedPasswordNotify = 0;
                }
            } catch (\Exception) {
                // log an error ?
            }
        }
    }
}
