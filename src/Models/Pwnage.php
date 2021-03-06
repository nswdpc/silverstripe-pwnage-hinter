<?php

namespace NSWDPC\Pwnage;

use MFlor\Pwned\Pwned;
use SilverStripe\Core\Config\Configurable;
use SilverStripe\Control\Email\Email;
use SilverStripe\ORM\ValidationException;
use SilverStripe\Security\Permission;

/**
 * Model for checking passwords and breaches and the like
 * @author James <james.ellis@dpc.nsw.gov.au>
 */
final class Pwnage
{

    use Configurable;

    /**
     * Your HIBP API key
     * @var string
     */
    private static $hibp_api_key = '';

    /**
     * Whether to check breached accounts as well
     * @var boolean
     */
    private static $check_breached_accounts = false;

    /**
     * Whether to allow pwned passwords
     * If false this adds a validation warning and records the fact against the member
     * @var boolean
     */
    private static $allow_pwned_passwords = false;

    /**
     * Whether to lock the account on breach
     * This is not currently implemented
     * @var boolean
     */
    private static $lock_account_on_breach = false;// TODO

    /**
     * Notify member on breach detection
     * This is not currently implemented
     * @var int
     */
    private static $notify_member_on_breach_detection = false;

    /**
     * Notify admin(s) on breach detection
     * This is not currently implemented
     * @var int
     */
    private static $notify_breach_account_digest = true;

    /**
     * Adds padding (Add-Padding in the API) to pwned password lookups
     * Read https://haveibeenpwned.com/API/v3#PwnedPasswordsPadding prior to changing to false
     * @var boolean
     */
    private static $pwned_password_include_padding = true;

    /**
     * HIBP breach option - when true, returns only the name of the breach.
     * @var boolean
     */
    private static $truncate_response = true;

    /**
     * HIBP breach option - filter result set to just this domain
     * @var string
     */
    private static $domain_filter = '';

    /**
     * HIBP breach option - include unverified breaches
     * @var boolean
     */
    private static $include_unverified = false;

    /**
     * Permission code to use for digest notification
     * @var string
     */
    private static $digest_permission_code = 'ADMIN';

    /**
     * Notify relevant group(s) with the configured permission code via a digest
     * @var boolean
     */
    private static $notify_pwned_password_digest = true;


    /**
     * Get groups that can be notified of pwned passwords
     */
    public function getDigestNotificationGroups() {
        $code = $this->config()->get('digest_permission_code');
        if(!$code) {
            return false;
        }
        $groups = Permission::get_groups_by_permission($code);
        return $groups;
    }

    /**
     * Check plain password using {@link MFlor\Pwned\Pwned} service client
     * @param string $password_plaintext
     * @returns int the number of breach occurrences
     */
    public function checkPassword($password_plaintext)
    {
        try {
            $error = "";
            $pwned = new Pwned();
            // note: {@link MFlor\Pwned\Repositories\PasswordRepository} hashes the password as required
            $occurences = $pwned->passwords()->occurrences(
                            $password_plaintext,
                            $this->config()->get('hibp_include_padding')
            );
            return $occurences;
        } catch (\Exception $e) {
            // TODO log?
            $error = $e->getMessage() ?: 'unknown error';
        }
        throw new ApiException($error);
    }

    /**
     * Check plain password using {@link MFlor\Pwned\Pwned} service client
     * @param string $password_plaintext
     * @returns array
     */
    public function checkBreachedAccount($email_address)
    {
        try {
            if (!Email::is_valid_address($email_address)) {
                throw new ValidationException(
                    _t(
                        Pwnage::class . ".EMAIL_NOT_VALID",
                        "Email address provided is not valid"
                    )
                );
            }

            $key = $this->config()->get('hibp_api_key');
            if (!$key) {
                throw new ApiException(
                    _t(
                        Pwnage::class . ".HIBP_KEY_REQUIRED_FOR_ACTION",
                        "HIBP API key required to perform this action"
                    )
                );
            }

            $error = "";
            $options = [
                'truncateResponse' => $this->config()->get('hibp_truncate_response'),
                'domain' => $this->config()->get('hibp_domain_filter'),
                'includeUnverified' => $this->config()->get('hibp_include_unverified')
            ];
            $pwned = new Pwned($key);
            $breaches = $pwned->breaches()->byAccount($email_address, $options);
            return $breaches;
        } catch (\Exception $e) {
            $error = $e->getMessage() ?: "unknown";
        }
        throw new ApiException($error);
    }

    /**
     * Get count of breaches for an account
     * @returns int
     * @param string $email_address
     */
    public function getBreachedAccountCount($email_address)
    {
        try {
            $result = $this->checkBreachedAccount($email_address);
            if (is_array($result)) {
                return count($result);
            } else {
                return 0;
            }
        } catch (\Exception $e) {
            $error = $e->getMessage() ?: "unknown";
        }
        throw new ApiException($error);
    }
}
