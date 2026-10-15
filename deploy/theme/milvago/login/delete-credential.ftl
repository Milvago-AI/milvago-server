<#import "template.ftl" as layout>
<@layout.registrationLayout displayMessage=false eyebrow="mvEyebrowSecurity"; section>
    <#if section = "header">
        ${msg("mvDeleteTitle", credentialLabel)}
    <#elseif section = "form">
        <p class="entry-description" id="kc-delete-text">${msg("mvDeleteText")}</p>
        <div class="notice warning"><@layout.icon "warning"/><p>${msg("mvDeleteLastWarning")}</p></div>
        <form class="actions" action="${url.loginAction}" method="post">
            <button class="button danger" name="accept" id="kc-accept" type="submit" value="on"><@layout.icon "trash"/>${msg("mvDeleteConfirm")}</button>
            <button class="link quiet" name="cancel-aia" id="kc-decline" type="submit" value="true">${msg("doCancel")}</button>
        </form>
    </#if>
</@layout.registrationLayout>
