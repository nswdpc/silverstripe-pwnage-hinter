<% include PwnageEmailHeader %>

    <table class="main" width="100%" cellpadding="0" cellspacing="0" style="font-family: {$FontFamily.XML}; box-sizing: border-box; font-size: 14px; border-radius: 3px; background-color: #fff; margin: 0; border: 1px solid #e9e9e9;" bgcolor="#fff">
        <tr style="font-family: {$FontFamily.XML}; box-sizing: border-box; font-size: 14px; margin: 0;">
            <td class="alert alert-warning" style="font-family: {$FontFamily.XML}; box-sizing: border-box; font-size: 16px; vertical-align: top; color: #fff; font-weight: 500; text-align: center; border-radius: 3px 3px 0 0; background-color: #FF9F00; margin: 0; padding: 20px;" align="center" bgcolor="#FF9F00" valign="top">

            {$Warning.XML}

            </td>
        </tr>
        <tr style="font-family: {$FontFamily.XML}; box-sizing: border-box; font-size: 14px; margin: 0;">
            <td class="content-wrap" style="font-family: {$FontFamily.XML}; box-sizing: border-box; font-size: 14px; vertical-align: top; margin: 0; padding: 20px;" valign="top">
                <table width="100%" cellpadding="0" cellspacing="0" style="font-family: {$FontFamily.XML}; box-sizing: border-box; font-size: 14px; margin: 0;">

                    <% end_if %>

                    <tr style="font-family: {$FontFamily.XML}; box-sizing: border-box; font-size: 14px; margin: 0;">
                        <td class="content-block" style="font-family: {$FontFamily.XML}; box-sizing: border-box; font-size: 14px; vertical-align: top; margin: 0; padding: 0 0 20px;" valign="top">

                            {$Content}

                        </td>
                    </tr>

                    <% if $CTA %>
                    <tr style="font-family: {$FontFamily.XML}; box-sizing: border-box; font-size: 14px; margin: 0;">
                        <td class="content-block" style="font-family: {$FontFamily.XML}; box-sizing: border-box; font-size: 14px; vertical-align: top; margin: 0; padding: 0 0 20px;" valign="top">

                        <a href="{$CTA.URL.XML}" class="btn-primary" style="font-family: {$FontFamily.XML}; box-sizing: border-box; font-size: 14px; color: #FFF; text-decoration: none; line-height: 2em; font-weight: bold; text-align: center; cursor: pointer; display: inline-block; border-radius: 5px; text-transform: capitalize; background-color: #348eda; margin: 0; border-color: #348eda; border-style: solid; border-width: 10px 20px;">{$CTA.Text.XML}</a>

                        </td>
                    </tr>
                    <% end_if %>

                    <% if $SignOff %>
                    <tr style="font-family: {$FontFamily.XML}; box-sizing: border-box; font-size: 14px; margin: 0;">
                        <td class="content-block" style="font-family: {$FontFamily.XML}; box-sizing: border-box; font-size: 14px; vertical-align: top; margin: 0; padding: 0 0 20px;" valign="top">

                            {$SignOff.XML}

                        </td>
                    </tr>
                    <% end_if %>

                </table>
            </td>
        </tr>
    </table>

<% include PwnageEmailFooter %>
