# Notifications

## Configuration

### font_family

The default value for email templates is:

```
system-ui, BlinkMacSystemFont, 'Noto Sans', Helvetica, Arial, sans-serif, 'Noto Color Emoji', 'Apple Color Emoji'
```

### email_from


Change value to be the email address notifications will come from

e.g "security@example.com"

Default: noreply@localhost

### email_from_name

Change value to be the name emails will come from
e.g "My Company Security Division"

Default: 'Account notifier'

## Templates

Email templates can be overridden in your theme, just place the following includes and templates in the same location in your theme/<theme_name>/templates directory and edit as required. The templates shipped with this module are provided as a guide.

```
Includes
    PwnageEmailHeader.ss -> email header
    PwnageEmailFooter.ss -> email footer
NSWDPC
    Pwnage
        BreachDigestContent.ss -> template used to hold content for recipients of the digest
        BreachedAccountDigest.ss -> the email template for breached account digest emails
        BreachedAccountNotification.ss -> the email template for breached account notifications
        MemberBreach.ss -> content part for the BreachedAccountNotification email
        PasswordDigestContent.ss -> template used to hold content for recipients of the digest
        PwnedPasswordDigest.ss -> the email template for pwned password digest emails
```
