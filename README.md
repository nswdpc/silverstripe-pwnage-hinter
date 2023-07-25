# Silverstripe pwnage hinter

This module allows verification of hashed passwords against the HIBP corpus.

For more information on how the Pwned Password API works, including how compromised password hashes are sent to the API, please read: https://haveibeenpwned.com/API/v3#PwnedPasswords

> This module is under active development and should not be considered production-ready just yet
>
> We welcome testing and feedback via the Github issue tracker

## Background

This module uses [MFlor/pwned](https://github.com/MFlor/pwned) to interface with the Password and Breach API.

In addition to password checking it can optionally check for breaches linked to a supplied email address, which requires an API key to be purchased from [haveibeenpwned](https://haveibeenpwned.com/API/Key)

From a Silverstripe perspective, the module:

+ checks for pwned passwords and prohibits their use via a ```PasswordValidator``` extension
+ flag relevant records
+ sends digest emails containing volume of pwned passwords

## Configuration

The module comes with a default configuration that should get you up and running.

Read [the configuration documentation](./docs/en/index.md) for configuration instructions

Read [the email documentation](./docs/en/002_email.md) for information about email and templates

## License

[BSD-3-Clause](./LICENSE.md)

## Documentation

* [Documentation](./docs/en/001_index.md)

## Maintainers

+ [dpcdigital@NSWDPC:~$](https://dpc.nsw.gov.au)

## Bugtracker

We welcome bug reports, pull requests and feature requests on the Github Issue tracker for this project.

Please review the [code of conduct](./code-of-conduct.md) prior to opening a new issue.

## Development and contribution

If you would like to make contributions to the module please ensure you raise a pull request and discuss with the module maintainers.

Please review the [code of conduct](./code-of-conduct.md) prior to completing a pull request.
