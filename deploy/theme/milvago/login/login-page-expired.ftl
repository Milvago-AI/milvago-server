<#import "template.ftl" as layout>
<@layout.registrationLayout eyebrow="mvEyebrowError" status="clock"; section>
    <#if section = "header">
        ${msg("mvExpiredTitle")}
    <#elseif section = "form">
        <p class="entry-description">${msg("mvExpiredText")}</p>
        <div class="actions">
            <a class="button primary" id="loginRestartLink" href="${url.loginRestartFlowUrl}">${msg("mvStartAgain")}<@layout.icon "arrow"/></a>
            <a class="link quiet" id="loginContinueLink" href="${url.loginAction}">${msg("mvContinueWhereLeft")}</a>
        </div>
    </#if>
</@layout.registrationLayout>
