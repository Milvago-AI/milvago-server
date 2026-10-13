<#import "template.ftl" as layout>
<#assign failed = messagesPerField.existsError('username')>
<@layout.registrationLayout displayMessage=!failed eyebrow="mvEyebrowReset"; section>
    <#if section = "header">
        ${msg("mvResetTitle")}
    <#elseif section = "form">
        <p class="entry-description">${msg("mvResetIntro")}</p>
        <form id="kc-reset-password-form" class="auth" action="${url.loginAction}" method="post">
            <div class="field">
                <label class="label" for="username">${msg("mvEmailOrUsername")}</label>
                <input class="input" type="text" id="username" name="username" value="${(auth.attemptedUsername)!''}" autofocus autocomplete="username" autocapitalize="none" spellcheck="false" dir="ltr"<#if failed> aria-invalid="true" aria-describedby="username-error"</#if>/>
                <#if failed><p class="field-error" id="username-error" aria-live="polite"><@layout.icon "alert"/><span>${kcSanitize(messagesPerField.get('username'))?no_esc}</span></p></#if>
            </div>
            <div class="actions">
                <button class="button primary" type="submit">${msg("mvSendLink")}<@layout.icon "arrow"/></button>
                <a class="link quiet" href="${url.loginUrl}">${msg("backToLogin")}</a>
            </div>
        </form>
    </#if>
</@layout.registrationLayout>
