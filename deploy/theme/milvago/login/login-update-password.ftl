<#import "template.ftl" as layout>
<#import "password-commons.ftl" as passwordCommons>
<#assign newFailed = messagesPerField.existsError('password')>
<#assign confirmFailed = messagesPerField.existsError('password-confirm')>
<@layout.registrationLayout displayMessage=!(newFailed || confirmFailed) eyebrow="mvEyebrowSecurity"; section>
    <#if section = "header">
        ${msg("mvNewPasswordTitle")}
    <#elseif section = "form">
        <form id="kc-passwd-update-form" class="auth" action="${url.loginAction}" method="post">
            <div class="field">
                <label class="label" for="password-new">${msg("passwordNew")}</label>
                <@layout.passwordField id="password-new" name="password-new" autocomplete="new-password" autofocus=true error=newFailed?then(messagesPerField.get('password'), "")/>
                <#-- Only the rules this realm enforces, checked off as the person types. -->
                <#if passwordPolicies??>
                <ul class="rules" data-rules-for="password-new" aria-label="${msg('mvPasswordRules')}">
                    <#if (passwordPolicies.length!0) gt 0><li data-rule="length" data-min="${passwordPolicies.length?c}">${msg("mvRuleLength", passwordPolicies.length?c)}</li></#if>
                    <#if (passwordPolicies.upperCase!0) gt 0><li data-rule="upperCase" data-min="${passwordPolicies.upperCase?c}">${msg("mvRuleUpper", passwordPolicies.upperCase?c)}</li></#if>
                    <#if (passwordPolicies.lowerCase!0) gt 0><li data-rule="lowerCase" data-min="${passwordPolicies.lowerCase?c}">${msg("mvRuleLower", passwordPolicies.lowerCase?c)}</li></#if>
                    <#if (passwordPolicies.digits!0) gt 0><li data-rule="digits" data-min="${passwordPolicies.digits?c}">${msg("mvRuleDigits", passwordPolicies.digits?c)}</li></#if>
                    <#if (passwordPolicies.specialChars!0) gt 0><li data-rule="specialChars" data-min="${passwordPolicies.specialChars?c}">${msg("mvRuleSpecial", passwordPolicies.specialChars?c)}</li></#if>
                </ul>
                </#if>
            </div>

            <div class="field">
                <label class="label" for="password-confirm">${msg("passwordConfirm")}</label>
                <@layout.passwordField id="password-confirm" name="password-confirm" autocomplete="new-password" error=confirmFailed?then(messagesPerField.get('password-confirm'), "")/>
            </div>

            <@passwordCommons.logoutOtherSessions/>

            <div class="actions">
                <button class="button primary" name="login" type="submit">${msg("mvSavePassword")}</button>
                <#if isAppInitiatedAction??><button class="link quiet" type="submit" name="cancel-aia" value="true">${msg("doCancel")}</button></#if>
            </div>
        </form>
    </#if>
</@layout.registrationLayout>
