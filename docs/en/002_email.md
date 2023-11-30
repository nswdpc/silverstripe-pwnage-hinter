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
