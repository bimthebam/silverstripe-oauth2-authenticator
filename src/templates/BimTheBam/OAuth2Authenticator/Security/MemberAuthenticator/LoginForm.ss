<% if $OAuth2Provider %>
    <h2><%t BimTheBam\OAuth2Authenticator\Security\MemberAuthenticator\LoginForm.LOGIN_WITH 'Login with' %></h2>

    <% loop $OAuth2Provider %>
        <p>
            <a href="{$InitAuthFlowURL}"><% if $Icon %>{$Icon}<% else %>{$Title}<% end_if %></a>
        </p>
    <% end_loop %>
<% end_if %>
