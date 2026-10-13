<#import "template.ftl" as layout>
<#assign failed = messagesPerField.existsError('totp')>
<@layout.registrationLayout displayMessage=!failed eyebrow="mvEyebrowVerify"; section>
    <#if section = "header">
        ${msg("mvOtpTitle")}
    <#elseif section = "form">
        <p class="entry-description">${msg("mvOtpIntro")}</p>
        <form id="kc-otp-login-form" class="auth" action="${url.loginAction}" method="post">
            <#if otpLogin.userOtpCredentials?size gt 1>
            <fieldset class="choices">
                <legend class="sr-only">${msg("mvDevice")}</legend>
                <#list otpLogin.userOtpCredentials as device>
                <label class="choice">
                    <input id="kc-otp-credential-${device?index}" type="radio" name="selectedCredentialId" value="${device.id}"<#if device.id == otpLogin.selectedCredentialId> checked</#if>/>
                    <@layout.icon "phone"/>
                    <div><strong>${(device.userLabel?has_content)?then(device.userLabel, msg("mvUnnamedDevice"))}</strong></div>
                </label>
                </#list>
            </fieldset>
            </#if>

            <div class="field">
                <label class="label" for="otp">${msg("mvOtpLabel")}</label>
                <input class="input otp" id="otp" name="otp" type="text" inputmode="numeric" pattern="[0-9]*" maxlength="6" autocomplete="one-time-code" autofocus dir="ltr" data-auto-submit aria-describedby="otp-hint<#if failed> otp-error</#if>"<#if failed> aria-invalid="true"</#if>/>
                <#if failed><p class="field-error" id="otp-error" aria-live="polite"><@layout.icon "alert"/><span>${kcSanitize(messagesPerField.get('totp'))?no_esc}</span></p></#if>
                <p class="field-hint" id="otp-hint">${msg("mvOtpHint")}</p>
            </div>

            <div class="actions">
                <button class="button primary" name="login" id="kc-login" type="submit">${msg("mvVerify")}<@layout.icon "arrow"/></button>
            </div>
        </form>
        <p class="field-hint">${msg("mvOtpLost")}</p>
    </#if>
</@layout.registrationLayout>
