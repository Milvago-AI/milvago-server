<#import "template.ftl" as layout>
<#import "password-commons.ftl" as passwordCommons>
<#assign codeFailed = messagesPerField.existsError('totp')>
<#assign labelFailed = messagesPerField.existsError('userLabel')>
<@layout.registrationLayout displayMessage=!(codeFailed || labelFailed) eyebrow="mvEyebrowSecurity"; section>
    <#if section = "header">
        ${msg("mvTotpTitle")}
    <#elseif section = "form">
        <p class="entry-description">${msg("mvTotpIntro")}</p>
        <form id="kc-totp-settings-form" action="${url.loginAction}" method="post">
            <ol class="steps">
                <li class="done">
                    <div class="step-body">
                        <h2>${msg("mvTotpStep1")}</h2>
                        <p>${msg("mvTotpStep1Text")}</p>
                        <ul class="apps" id="kc-totp-supported-apps">
                            <#list totp.supportedApplications as app><li class="chip">${msg(app)}</li></#list>
                        </ul>
                    </div>
                </li>
                <li class="current">
                    <div class="step-body">
                        <h2>${msg("mvTotpStep2")}</h2>
                        <div class="qr">
                            <div class="qr-code"><img id="kc-totp-secret-qr-code" src="data:image/png;base64, ${totp.totpSecretQrCode}" alt="${msg('mvTotpQrAlt')}"/></div>
                            <details class="manual"<#if mode?? && mode = "manual"> open</#if>>
                                <summary>${msg("loginTotpUnableToScan")}</summary>
                                <p class="field-hint">${msg("mvTotpManual")}</p>
                                <div class="secret">
                                    <code id="kc-totp-secret-key">${totp.totpSecretEncoded}</code>
                                    <button class="button small" type="button" data-copy="kc-totp-secret-key" data-label-done="${msg('mvCopied')}"><@layout.icon "copy"/><span>${msg("mvCopy")}</span></button>
                                </div>
                            </details>
                        </div>
                    </div>
                </li>
                <li>
                    <div class="step-body">
                        <h2>${msg("mvTotpStep3")}</h2>
                        <div class="split">
                            <div class="field">
                                <label class="label" for="totp">${msg("mvOtpLabel")}</label>
                                <input class="input otp" type="text" id="totp" name="totp" inputmode="numeric" pattern="[0-9]*" maxlength="6" autocomplete="one-time-code" dir="ltr"<#if codeFailed> aria-invalid="true" aria-describedby="totp-error"</#if>/>
                                <#if codeFailed><p class="field-error" id="totp-error" aria-live="polite"><@layout.icon "alert"/><span>${kcSanitize(messagesPerField.get('totp'))?no_esc}</span></p></#if>
                            </div>
                            <div class="field">
                                <label class="label" for="userLabel">${msg("loginTotpDeviceName")}<#if totp.otpCredentials?size gte 1><span class="required">*</span><#else> <span class="field-hint">(${msg("mvOptional")})</span></#if></label>
                                <input class="input" type="text" id="userLabel" name="userLabel" autocomplete="off" placeholder="${msg('mvDevicePlaceholder')}" dir="ltr"<#if labelFailed> aria-invalid="true" aria-describedby="userLabel-error"</#if>/>
                                <#if labelFailed><p class="field-error" id="userLabel-error" aria-live="polite"><@layout.icon "alert"/><span>${kcSanitize(messagesPerField.get('userLabel'))?no_esc}</span></p></#if>
                            </div>
                        </div>
                    </div>
                </li>
            </ol>
            <input type="hidden" id="totpSecret" name="totpSecret" value="${totp.totpSecret}"/>
            <#if mode??><input type="hidden" id="mode" name="mode" value="${mode}"/></#if>
            <@passwordCommons.logoutOtherSessions/>
            <div class="actions">
                <button class="button primary" type="submit" id="saveTOTPBtn">${msg("mvTotpActivate")}</button>
                <#if isAppInitiatedAction??><button class="link quiet" type="submit" id="cancelTOTPBtn" name="cancel-aia" value="true">${msg("doCancel")}</button></#if>
            </div>
        </form>
    </#if>
</@layout.registrationLayout>
