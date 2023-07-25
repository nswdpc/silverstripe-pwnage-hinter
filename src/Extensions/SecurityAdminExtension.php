<?php

namespace NSWDPC\Pwnage;

use SilverStripe\Forms\LiteralField;
use SilverStripe\Core\Extension;
use SilverStripe\Core\Config\Config;

/**
 * Adds HIBP attribution information to the Security admin section
 */
class SecurityAdminExtension extends Extension
{
    public function updateEditForm($form)
    {
        $fields = $form->Fields();
        if ($fields) {
            $fields->insertAfter(
                'users',
                LiteralField::create(
                    'PwnedPasswordAttribution',
                    '<div class="alert alert-info">'
                    . strip_tags(
                        _t(
                            Pwnage::class . ".ATTRIBUTION",
                            "We use the 'Have I Been Pwned' service to check whether your password has appeared in a data breach under the terms of the Creative Commons Attribution 4.0 International License."
                        )
                    )
                    . '</div>'
                )
            );
        }
    }
}
