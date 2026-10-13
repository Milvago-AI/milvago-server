<#-- Frame of every identity page: the console entry page, line for line (header, central
     column, three arguments aside, footer), so moving between the console and these pages
     changes only the central block. Keycloak's own pages that this theme does not rewrite
     are drawn inside it too. No inline script or style: values the script needs travel in
     data-* attributes. -->
<#-- Where "Change" and "Start again" lead: the console entry page, which routes the
     address typed to its organization. The client's base URL is the console sign-in in the
     root realm and the entry page in a child one; without one, Keycloak restarts its flow. -->
<#assign milvagoHome = url.loginRestartFlowUrl>
<#if client?? && (client.baseUrl!"")?has_content>
    <#assign milvagoHome = client.baseUrl?remove_ending("/auth/login")>
    <#if !milvagoHome?ends_with("/")><#assign milvagoHome = milvagoHome + "/"></#if>
</#if>

<#macro icon name>
<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><#switch name>
<#case "arrow"><path d="M5 12h14"/><path d="m12 5 7 7-7 7"/><#break>
<#case "arrowLeft"><path d="m12 19-7-7 7-7"/><path d="M19 12H5"/><#break>
<#case "eye"><path d="M2.06 12.35a1 1 0 0 1 0-.7 10.75 10.75 0 0 1 19.88 0 1 1 0 0 1 0 .7 10.75 10.75 0 0 1-19.88 0"/><circle cx="12" cy="12" r="3"/><#break>
<#case "eyeOff"><path d="M10.73 5.08a10.74 10.74 0 0 1 11.2 6.57 1 1 0 0 1 0 .7 10.75 10.75 0 0 1-1.44 2.49"/><path d="M14.08 14.16a3 3 0 0 1-4.24-4.24"/><path d="M17.48 17.5a10.75 10.75 0 0 1-15.42-5.15 1 1 0 0 1 0-.7 10.75 10.75 0 0 1 4.45-5.14"/><path d="m2 2 20 20"/><#break>
<#case "sun"><circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.93 4.93l1.41 1.41M17.66 17.66l1.41 1.41M2 12h2M20 12h2M6.34 17.66l-1.41 1.41M19.07 4.93l-1.41 1.41"/><#break>
<#case "moon"><path d="M12 3a6 6 0 0 0 9 9 9 9 0 1 1-9-9Z"/><#break>
<#case "chevron"><path d="m6 9 6 6 6-6"/><#break>
<#case "alert"><circle cx="12" cy="12" r="10"/><path d="M12 8v4"/><path d="M12 16h.01"/><#break>
<#case "warning"><path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3"/><path d="M12 9v4"/><path d="M12 17h.01"/><#break>
<#case "info"><circle cx="12" cy="12" r="10"/><path d="M12 16v-4"/><path d="M12 8h.01"/><#break>
<#case "check"><path d="M20 6 9 17l-5-5"/><#break>
<#case "mail"><rect width="20" height="16" x="2" y="4" rx="2"/><path d="m22 7-8.97 5.7a1.94 1.94 0 0 1-2.06 0L2 7"/><#break>
<#case "clock"><circle cx="12" cy="12" r="10"/><path d="M12 6v6l4 2"/><#break>
<#case "copy"><rect width="14" height="14" x="8" y="8" rx="2"/><path d="M4 16c-1.1 0-2-.9-2-2V4c0-1.1.9-2 2-2h10c1.1 0 2 .9 2 2"/><#break>
<#case "trash"><path d="M3 6h18"/><path d="M19 6v14c0 1-1 2-2 2H7c-1 0-2-1-2-2V6"/><path d="M8 6V4c0-1 1-2 2-2h4c1 0 2 1 2 2v2"/><#break>
<#case "phone"><rect width="14" height="20" x="5" y="2" rx="2"/><path d="M12 18h.01"/><#break>
<#case "lock"><rect width="18" height="11" x="3" y="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/><#break>
<#case "map"><path d="M14.1 6.03a2 2 0 0 0 1.79 0l3.66-1.83A1 1 0 0 1 21 5.1v12.38a1 1 0 0 1-.55.9l-4.56 2.28a2 2 0 0 1-1.79 0l-4.21-2.1a2 2 0 0 0-1.79 0L4.45 20.4A1 1 0 0 1 3 19.5V7.12a1 1 0 0 1 .55-.9l4.56-2.28a2 2 0 0 1 1.79 0z"/><path d="M15 5.76v15"/><path d="M9 3.24v15"/><#break>
<#case "shield"><path d="M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.24-2.72a1.17 1.17 0 0 1 1.52 0C14.51 3.81 17 5 19 5a1 1 0 0 1 1 1z"/><#break>
</#switch></svg>
</#macro>

<#-- The person signing in, shown instead of a field once Keycloak knows them. -->
<#macro identity name change=true>
<div class="identity">
    <span class="avatar" aria-hidden="true">${name?substring(0, 1)}</span>
    <span class="identity-email">${name}</span>
    <#if change><a href="${milvagoHome}">${msg("mvChange")}</a></#if>
</div>
</#macro>

<#macro passwordField id name autocomplete error="" autofocus=false>
<div class="input-group">
    <input class="input" id="${id}" name="${name}" type="password" autocomplete="${autocomplete}" dir="ltr"<#if autofocus> autofocus</#if><#if error?has_content> aria-invalid="true" aria-describedby="${id}-error"</#if>/>
    <button class="icon-button reveal" type="button" data-reveal="${id}" aria-label="${msg('showPassword')}" data-label-show="${msg('showPassword')}" data-label-hide="${msg('hidePassword')}">
        <span class="reveal-show"><@icon "eye"/></span><span class="reveal-hide" hidden><@icon "eyeOff"/></span>
    </button>
</div>
<#if error?has_content><p class="field-error" id="${id}-error" aria-live="polite"><@icon "alert"/><span>${kcSanitize(error)?no_esc}</span></p></#if>
</#macro>

<#-- Keycloak's eyebrow for the pages this theme does not name itself. -->
<#assign eyebrows = {
    "login": "mvEyebrowSignIn", "login-password": "mvEyebrowSignIn", "login-username": "mvEyebrowSignIn",
    "login-otp": "mvEyebrowVerify", "select-authenticator": "mvEyebrowVerify", "webauthn-authenticate": "mvEyebrowVerify",
    "login-recovery-authn-code-input": "mvEyebrowVerify",
    "login-reset-password": "mvEyebrowReset", "login-reset-otp": "mvEyebrowReset",
    "error": "mvEyebrowError", "login-page-expired": "mvEyebrowError"
}>

<#macro registrationLayout bodyClass="" displayInfo=false displayMessage=true displayRequiredFields=false eyebrow="" status="">
<!DOCTYPE html>
<html lang="${lang}"<#if realm.internationalizationEnabled> dir="${(locale.rtl)?then('rtl','ltr')}"</#if>>
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta name="robots" content="noindex, nofollow">
    <meta name="color-scheme" content="dark light">
    <title>Milvago</title>
    <link rel="icon" href="${url.resourcesPath}/img/favicon.svg" type="image/svg+xml">
    <#list (properties.styles!"")?split(' ') as style><#if style?has_content>
    <link href="${url.resourcesPath}/${style}" rel="stylesheet">
    </#if></#list>
    <#list (properties.scripts!"")?split(' ') as script><#if script?has_content>
    <script src="${url.resourcesPath}/${script}"></script>
    </#if></#list>
    <#-- Keycloak's own pages that carry a script (security keys, passkeys) resolve this module by name. -->
    <script type="importmap">{"imports": {"rfc4648": "${url.resourcesCommonPath}/vendor/rfc4648/rfc4648.js"}}</script>
    <#if scripts??><#list scripts as script>
    <script src="${script}"></script>
    </#list></#if>
</head>
<body class="${bodyClass}" data-page-id="login-${pageId}" data-resources="${url.resourcesPath}" data-sso-poll="${url.ssoLoginInOtherTabsUrl}"<#if authenticationSession??> data-auth-session="${authenticationSession.authSessionIdHash}"</#if>>
<div class="entry">
    <header class="entry-header">
        <span class="brand"><span class="brand-mark" aria-hidden="true"></span><span class="brand-name">Milvago</span></span>
        <div class="preferences">
            <button class="icon-button theme-toggle" type="button" data-theme-toggle data-label-light="${msg('mvThemeLight')}" data-label-dark="${msg('mvThemeDark')}" aria-label="${msg('mvThemeLight')}">
                <span class="theme-light-icon"><@icon "sun"/></span><span class="theme-dark-icon"><@icon "moon"/></span>
            </button>
            <#if realm.internationalizationEnabled && locale.supported?size gt 1>
            <details class="lang">
                <summary aria-label="${msg('languages')}">${locale.current} <@icon "chevron"/></summary>
                <ul>
                    <#list locale.supported as l>
                    <li><a href="${l.url}" lang="${l.languageTag}"<#if l.languageTag == locale.currentLanguageTag> aria-current="true"</#if>>${l.label}</a></li>
                    </#list>
                </ul>
            </details>
            </#if>
        </div>
    </header>

    <main class="entry-main">
        <#if status?has_content>
        <#assign statusTones = {"success": "success", "clock": "warning", "warning": "warning", "mail": "info", "info": "info"}>
        <span class="status-icon ${statusTones[status]!'info'}"><@icon (status == 'success')?then('check', status)/></span>
        </#if>
        <p class="eyebrow">${msg(eyebrow?has_content?then(eyebrow, eyebrows[pageId]!"mvEyebrowAccount"))}</p>
        <h1 id="kc-page-title"><#nested "header"></h1>

        <#if auth?has_content && auth.showUsername() && !auth.showResetCredentials()>
            <#nested "show-username">
            <@identity name=auth.attemptedUsername change=!(isAppInitiatedAction??) && !(usernameHidden??)/>
        </#if>

        <#-- Application-initiated actions do not need the warning that asks to complete them. -->
        <#if displayMessage && message?has_content && (message.type != 'warning' || !isAppInitiatedAction??)>
        <div class="notice ${message.type}" role="${(message.type == 'error')?then('alert', 'status')}">
            <@icon (message.type == 'success')?then('check', (message.type == 'info')?then('info', (message.type == 'warning')?then('warning', 'alert')))/>
            <p>${kcSanitize(message.summary)?no_esc}</p>
        </div>
        </#if>

        <#if displayRequiredFields>
        <p class="field-hint"><span class="required">*</span> ${msg("requiredFields")}</p>
        </#if>

        <#nested "form">

        <#if auth?has_content && auth.showTryAnotherWayLink()>
        <form id="kc-select-try-another-way-form" action="${url.loginAction}" method="post">
            <input type="hidden" name="tryAnotherWay" value="on"/>
            <button class="link quiet" type="submit" id="try-another-way">${msg("doTryAnotherWay")}</button>
        </form>
        </#if>

        <#if switchOrganizationEnabled?? && switchOrganizationEnabled>
        <form id="kc-switch-organization-form" action="${url.loginAction}" method="post">
            <input type="hidden" name="switchOrganization" value="true"/>
            <button class="link quiet" type="submit" id="switch-organization">${msg("doSwitchOrganization")}</button>
        </form>
        </#if>

        <#nested "socialProviders">

        <#if displayInfo>
        <div id="kc-info" class="field-hint"><#nested "info"></div>
        </#if>
    </main>

    <aside class="entry-aside">
        <div class="entry-value"><@icon "eye"/><div><strong>${msg("mvObserve")}</strong><span>${msg("mvObserveText")}</span></div></div>
        <div class="entry-value"><@icon "map"/><div><strong>${msg("mvUnderstand")}</strong><span>${msg("mvUnderstandText")}</span></div></div>
        <div class="entry-value"><@icon "shield"/><div><strong>${msg("mvDecide")}</strong><span>${msg("mvDecideText")}</span></div></div>
    </aside>

    <footer class="entry-footer"><span>Milvago</span><span></span></footer>
</div>
</body>
</html>
</#macro>
