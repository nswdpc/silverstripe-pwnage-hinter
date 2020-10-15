
<% if $MemberCount > 0 %>
    <p>Some accounts on your website have attempted to sign in with a pwned password since the last notification.</p>
    <p>The current count is: {$MemberCount}</p>
<% else %>
    <p>No accounts have attempted to sign in with a pwned password since the last notification</p>
<% end_if %>

<p>To view the current report, sign in to the administration area and filter the user list appropriately</p>
