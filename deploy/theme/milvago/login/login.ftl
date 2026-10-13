<#import "template.ftl" as layout>
<#-- The address typed on the console entry page arrives as the username: it is shown as
     who is signing in, with the way back to change it, rather than as a field to retype. -->
<#assign hint = (login.username)!"">
<#assign failed = messagesPerField.existsError('username','password')>
<@layout.registrationLayout displayMessage=!failed displayInfo=false eyebrow=(usernameHidden??)?then("mvEyebrowStepUp", "mvEyebrowSignIn"); section>
    <#if section = "header">
        <#if usernameHidden??>${msg("mvStepUpTitle")}<#elseif hint?has_content>${msg("mvSignInBackTitle")}<#else>${msg("mvSignInTitle")}</#if>
    <#elseif section = "form">
        <#if usernameHidden??><p class="entry-description">${msg("reauthenticate")}</p></#if>
        <#if realm.password>
        <form id="kc-form-login" class="auth" action="${url.loginAction}" method="post">
            <#if !usernameHidden??>
                <#if hint?has_content>
                    <@layout.identity name=hint/>
                    <input type="hidden" id="username" name="username" value="${hint}"/>
                <#else>
                    <div class="field">
                        <label class="label" for="username">${msg("mvEmailOrUsername")}</label>
                        <input class="input" id="username" name="username" type="text" value="${hint}" autofocus autocomplete="username" autocapitalize="none" spellcheck="false" dir="ltr"<#if failed> aria-invalid="true"</#if>/>
                    </div>
                </#if>
            </#if>

            <div class="field">
                <div class="field-head">
                    <label class="label" for="password">${msg("password")}</label>
                    <#if realm.resetPasswordAllowed && !usernameHidden??><a class="link quiet" href="${url.loginResetCredentialsUrl}">${msg("doForgotPassword")}</a></#if>
                </div>
                <@layout.passwordField id="password" name="password" autocomplete="current-password" autofocus=(hint?has_content || usernameHidden??) error=failed?then(messagesPerField.getFirstError('username','password'), "")/>
                <p class="field-warning" data-caps-for="password" hidden><@layout.icon "warning"/><span>${msg("mvCapsLock")}</span></p>
            </div>

            <#if realm.rememberMe && !usernameHidden??>
            <label class="check"><input id="rememberMe" name="rememberMe" type="checkbox"<#if login.rememberMe??> checked</#if>/> ${msg("rememberMe")}</label>
            </#if>

            <input type="hidden" id="id-hidden-input" name="credentialId"<#if auth.selectedCredential?has_content> value="${auth.selectedCredential}"</#if>/>
            <div class="actions">
                <button class="button primary" name="login" id="kc-login" type="submit">${msg("mvContinue")}<@layout.icon "arrow"/></button>
                <#if usernameHidden??><a class="link quiet" href="${layout.milvagoHome}">${msg("doCancel")}</a></#if>
            </div>
        </form>
        </#if>
    <#elseif section = "socialProviders">
        <#-- Only the providers an administrator enabled for this organization; an address of a
             proven domain never reaches this page, the entry page sends it to its provider. -->
        <#if realm.password && social?? && social.providers?has_content && !usernameHidden??>
        <div class="mv-sso-section">
            <p class="mv-or">${msg("mvOr")}</p>
            <ul class="mv-sso">
                <#list social.providers as p>
                <li>
                    <a class="button" id="social-${p.alias}" href="${p.loginUrl}" data-once-link>
                        <#if p.alias == "microsoft">
                        <svg viewBox="0 0 21 21" width="18" height="18" aria-hidden="true"><path fill="#F25022" d="M0 0h10v10H0z"/><path fill="#7FBA00" d="M11 0h10v10H11z"/><path fill="#00A4EF" d="M0 11h10v10H0z"/><path fill="#FFB900" d="M11 11h10v10H11z"/></svg>
                        <#elseif p.alias == "google">
                        <svg viewBox="0 0 48 48" width="18" height="18" aria-hidden="true"><path fill="#EA4335" d="M24 9.5c3.54 0 6.71 1.22 9.21 3.6l6.85-6.85C35.9 2.38 30.47 0 24 0 14.62 0 6.51 5.38 2.56 13.22l7.98 6.19C12.43 13.72 17.74 9.5 24 9.5z"/><path fill="#4285F4" d="M46.98 24.55c0-1.57-.15-3.09-.38-4.55H24v9.02h12.94c-.58 2.96-2.26 5.48-4.78 7.18l7.73 6c4.51-4.18 7.09-10.36 7.09-17.65z"/><path fill="#FBBC05" d="M10.53 28.59c-.48-1.45-.76-2.99-.76-4.59s.27-3.14.76-4.59l-7.98-6.19C.92 16.46 0 20.12 0 24c0 3.88.92 7.54 2.56 10.78l7.97-6.19z"/><path fill="#34A853" d="M24 48c6.48 0 11.93-2.13 15.89-5.81l-7.73-6c-2.15 1.45-4.92 2.3-8.16 2.3-6.26 0-11.57-4.22-13.47-9.91l-7.98 6.19C6.51 42.62 14.62 48 24 48z"/></svg>
                        </#if>
                        <span>${msg("mvContinueWith", (p.displayName)!p.alias)}</span>
                    </a>
                </li>
                </#list>
            </ul>
        </div>
        </#if>
    </#if>
</@layout.registrationLayout>
