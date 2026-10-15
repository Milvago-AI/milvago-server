<#import "template.ftl" as layout>
<#-- Two pages in one: the welcome page of an invitation link, which lists what remains to
     do before the account works, and every other notice (account ready, e-mail updated). -->
<#assign welcome = requiredActions?? && requiredActions?has_content>
<#-- A new address waiting for its confirmation ends the change here, without going back
     through the console sign-in: the way back opens the profile with that confirmation. -->
<#assign emailPending = (messageHeader!"") == msg("emailUpdateConfirmationSentTitle") && client?? && (client.baseUrl!"")?has_content>
<@layout.registrationLayout displayMessage=false eyebrow=welcome?then("mvEyebrowActivation", "mvEyebrowAccount") status=welcome?then("", (((message.type)!"") == 'success')?then("success", "info")); section>
    <#if section = "header">
        <#if welcome>${msg("mvWelcomeTitle")}<#elseif messageHeader??>${kcSanitize(msg("${messageHeader}"))?no_esc}<#else>${message.summary}</#if>
    <#elseif section = "form">
        <#if welcome>
            <p class="entry-description">${msg("mvWelcomeIntro")}</p>
            <#-- Opening the e-mailed link is what proves the address: that step is already done. -->
            <#assign current = false>
            <ol class="steps">
                <#list requiredActions as action>
                <#if action == "VERIFY_EMAIL">
                <li class="done"><div class="step-body"><h2>${kcSanitize(msg("requiredAction.${action}"))?no_esc}</h2><p>${msg("mvWelcomeEmailDone")}</p></div></li>
                <#else>
                <li<#if !current> class="current"</#if>><div class="step-body"><h2>${kcSanitize(msg("requiredAction.${action}"))?no_esc}</h2></div></li>
                <#assign current = true>
                </#if>
                </#list>
            </ol>
            <p class="field-hint">${msg("mvWelcomeMfaNote")}</p>
        <#elseif messageHeader??>
            <p class="entry-description">${message.summary}</p>
        </#if>
        <#if !skipLink??>
        <div class="actions">
            <#if emailPending>
                <a class="button primary" href="${layout.milvagoHome}#profile?done=email&amp;status=success">${msg("backToApplication")}<@layout.icon "arrow"/></a>
            <#elseif pageRedirectUri?has_content>
                <a class="button primary" href="${pageRedirectUri}">${msg("backToApplication")}<@layout.icon "arrow"/></a>
            <#elseif actionUri?has_content>
                <a class="button primary" href="${actionUri}">${welcome?then(msg("mvStart"), msg("proceedWithAction"))}<@layout.icon "arrow"/></a>
            <#elseif (client.baseUrl)?has_content>
                <a class="button primary" href="${client.baseUrl}">${msg("backToApplication")}<@layout.icon "arrow"/></a>
            </#if>
        </div>
        </#if>
    </#if>
</@layout.registrationLayout>
