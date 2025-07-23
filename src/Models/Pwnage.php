<?php

namespace NSWDPC\Pwnage;

use MFlor\Pwned\Pwned;
use SilverStripe\Core\Config\Configurable;
use SilverStripe\Core\Injector\Injectable;
use SilverStripe\Control\Email\Email;
use SilverStripe\ORM\ValidationException;
use SilverStripe\Security\Permission;

/**
 * Model for checking passwords and breaches and the like
 */
class Pwnage
{
    use Configurable;
    use Injectable;

    /**
     * Your HIBP API key
     */
    private static string $hibp_api_key = '';

    /**
     * By default, check against configured pwned password corpus
     */
    private static bool $check_pwned_passwords = true;

    /**
     * Whether to allow pwned passwords
     * If false this adds a validation warning and records the fact against the member
     */
    private static bool $allow_pwned_passwords = false;

    /**
     * Adds padding (Add-Padding in the API) to pwned password lookups
     * Read https://haveibeenpwned.com/API/v3#PwnedPasswordsPadding prior to changing to false
     */
    private static bool $hibp_include_padding = true;

    /**
     * HIBP breach option - when true, returns only the name of the breach.
     */
    private static bool $hibp_truncate_response = true;

    /**
     * HIBP breach option - filter result set to just this domain
     */
    private static string $hibp_domain_filter = '';

    /**
     * HIBP breach option - include unverified breaches
     */
    private static bool $hibp_include_unverified = false;

    /**
     * Permission code to use for digest notification
     */
    private static string $digest_permission_code = 'ADMIN';

    /**
     * Notify relevant group(s) with the configured permission code via a digest
     */
    private static bool $notify_pwned_password_digest = true;

    /**
     * Return the Pwned API client
     */
    protected function getClient($api_key = null): Pwned
    {
        return new Pwned($api_key);
    }

    /**
     * Get groups that can be notified of pwned passwords
     */
    public function getDigestNotificationGroups()
    {
        $code = self::config()->get('digest_permission_code');
        if (!$code) {
            return false;
        }

        return Permission::get_groups_by_permission($code);
    }

    /**
     * Check plain password using {@link MFlor\Pwned\Pwned} service client
     * @returns int the number of breach occurrences
     */
    public function checkPassword(string $password_plaintext): int
    {
        try {
            $error = "";
            $pwned = $this->getClient();
            // note: {@link MFlor\Pwned\Repositories\PasswordRepository} hashes the password as required
            $occurences = $pwned->passwords()->occurrences(
                $password_plaintext,
                self::config()->get('hibp_include_padding')
            );
            return $occurences;
        } catch (\Exception $exception) {
            // TODO log?
            $error = $exception->getMessage();
        }

        throw new ApiException($error);
    }

    /**
     * Check email address using {@link MFlor\Pwned\Pwned} service client
     * @returns array
     */
    public function checkBreachedAccount(string $email_address): array
    {
        if (!Email::is_valid_address($email_address)) {
            throw \SilverStripe\Core\Validation\ValidationException::create(
                _t(
                    Pwnage::class . ".EMAIL_NOT_VALID",
                    "Email address provided is not valid"
                )
            );
        }

        $key = self::config()->get('hibp_api_key');
        if (!$key) {
            throw new ApiException(
                _t(
                    Pwnage::class . ".HIBP_KEY_REQUIRED_FOR_ACTION",
                    "HIBP API key required to perform this action"
                )
            );
        }

        $options = [
            'truncateResponse' => self::config()->get('hibp_truncate_response'),
            'domain' => self::config()->get('hibp_domain_filter'),
            'includeUnverified' => self::config()->get('hibp_include_unverified')
        ];

        $pwned = $this->getClient($key);
        $breaches = $pwned->breaches()->byAccount($email_address, $options);
        return $breaches ?? [];
    }

    /**
     * Get count of breaches for an account
     */
    public function getBreachedAccountCount(string $email_address): int
    {
        try {
            $result = $this->checkBreachedAccount($email_address);
            return count($result);
        } catch (\Exception $exception) {
            $error = $exception->getMessage();
        }

        throw new ApiException($error);
    }
}
