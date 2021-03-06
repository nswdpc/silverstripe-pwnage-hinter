# Configuration

The following values are configurable.

Configuration settings prefixed `hibp_` are specific to the haveibeenpwned and pwnedpassword APIs.

> To check for breached accounts using an email address, you must purchase a haveibeenpwned API key

## General options

### check_breached_accounts

Turn on/off breached account checked. Not much use turning this on if you don't have an API key ^

Default: false

### allow_pwned_passwords

Whether to allow compromised passwords or not

Default: false

Recommended: false

When this is set to true, the usage of a pwned password is logged against the member record.

### lock_account_on_breach

**(reserved)**

Whether to lock the Member account when a breach is found

Not in use.

Default : false

### notify_member_on_breach_detection

Whether to notify the Member account by email if their account is found to be in a known data breach.

Default : false

Recommended: false

Turning this on requires forward planning & careful consideration of how account holders will react to messages regarding breaches.

### digest_permission_code

Permission code to use for group selection of digest recipients.

Anyone in this group will receive digest emails regarding pwned password / breached account volumes.

Default: ADMIN

### notify_breach_account_digest

When true a digest email will be sent to users with the permission of `digest_permission_code` containing a count of breached accounts

Default : true

### notify_pwned_password_digest

When true a digest email will be sent to users with the permission of `digest_permission_code` containing a count of accounts with pwned password flags

Default : true

## HIBP API client options

These options are specific to the HIBP API

### hibp_api_key

Your [HIBP API Key](https://haveibeenpwned.com/API/Key).

Any request that includes an email address needs this.

Default: '' (empty string)

##3 hibp_include_padding

Whether to [include padding in the response](https://haveibeenpwned.com/API/v3#PwnedPasswordsPadding) in responses

Default: true

Recommended: true

### hibp_truncate_response

Whether to [truncate the response](https://haveibeenpwned.com/API/v3#BreachesForAccount)

Default: true

Recommended: true

### hibp_domain_filter

The [domain to filter on, optional](https://haveibeenpwned.com/API/v3#BreachesForAccount)

If you change this, notifications will be sent to account holders as the delta of breached sites for an account will most likely change.

Default: null

Recommended: null

### hibp_include_unverified

Whether to [include unverified breaches in a breach response](https://haveibeenpwned.com/API/v3#BreachesForAccount)

Default: false

Recommended: false
