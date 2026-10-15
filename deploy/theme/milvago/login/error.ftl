<#import "template.ftl" as layout>
<@layout.registrationLayout displayMessage=false eyebrow="mvEyebrowError" status="warning"; section>
    <#if section = "header">
        ${msg("mvErrorTitle")}
    <#elseif section = "form">
        <p class="entry-description" id="kc-error-message">${kcSanitize(message.summary)?no_esc}</p>
        <#if traceId??><p class="field-hint" id="traceId">${msg("traceIdSupportMessage", traceId)}</p></#if>
        <#if !skipLink?? && client?? && (client.baseUrl)?has_content>
        <div class="actions">
            <a class="button primary" id="backToApplication" href="${layout.milvagoHome}">${msg("mvStartAgain")}<@layout.icon "arrow"/></a>
        </div>
        </#if>
    </#if>
</@layout.registrationLayout>
