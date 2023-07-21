
<% if $MemberCount > 0 %>
    <p>Some accounts on your website are flagged as having a password flagged by HIBP.</p>
    <p>The current count is: {$MemberCount}</p>
<% else %>
    <p>No accounts on your website have a password flagged by HIBP.</p>
<% end_if %>

<p>To view the current report, sign in to the administration area and filter the user list appropriately.</p>
