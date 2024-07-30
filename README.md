# Silverstripe pwnage hinting

This module allows checking of passwords against the HIBP corpus.

For more information on how the Pwned Password API works, including how password hashes are sent to the API, please read: https://haveibeenpwned.com/API/v3#PwnedPasswords

## Background

This module uses [MFlor/pwned](https://github.com/MFlor/pwned) to interface with the Password and Breach API.

From a Silverstripe perspective, the module:

+ checks for pwned passwords and optionally prohibits (by default) their use via a `PasswordValidator` extension
+ flags relevant records
+ optionally sends digest emails containing volume of pwned passwords

In addition to password checking it can be used to check for breaches, or a count of breaches, linked to a supplied email address. Breach checking requires an API key to be purchased from [haveibeenpwned](https://haveibeenpwned.com/API/Key)

## Configuration

The module comes with a default configuration that should get you up and running.

Read [the configuration documentation](./docs/en/index.md) for configuration instructions

Read [the email documentation](./docs/en/002_email.md) for information about email and templates

## License

[BSD-3-Clause](./LICENSE.md)

## Documentation

* [Documentation](./docs/en/001_index.md)

## Maintainers

PD web team
## Bugtracker

We welcome bug reports, pull requests and feature requests on the Github Issue tracker for this project.

Please review the [code of conduct](./code-of-conduct.md) prior to opening a new issue.

## Security

If you have found a security issue with this module, please email digital[@]dpc.nsw.gov.au in the first instance, detailing your findings.

## Development and contribution

If you would like to make contributions to the module please ensure you raise a pull request and discuss with the module maintainers.

Please review the [code of conduct](./code-of-conduct.md) prior to completing a pull request.
