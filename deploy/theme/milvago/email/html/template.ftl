<#-- Frame of every e-mail Keycloak sends for Milvago, the ones this theme does not rewrite
     included. Inline styles and tables: mail clients ignore style sheets and most layout. -->
<#-- recipient: only for an e-mail sent somewhere else than the account's address. -->
<#macro emailLayout recipient="">
<#assign sentTo = recipient?has_content?then(recipient, (user.email)!"")>
<!DOCTYPE html>
<html lang="${locale.language}" dir="${(ltr)?then('ltr','rtl')}">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="light">
<title>Milvago</title>
</head>
<body style="margin:0;padding:0;background:#F3F6FA;">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="background:#F3F6FA;">
<tr><td align="center" style="padding:32px 16px;">
<table role="presentation" width="560" cellpadding="0" cellspacing="0" border="0" style="width:100%;max-width:560px;font-family:Inter,'Segoe UI',Helvetica,Arial,sans-serif;color:#172033;">
<tr><td style="padding:0 4px 16px;font-size:17px;font-weight:600;letter-spacing:-0.2px;color:#172033;"><span style="display:inline-block;width:22px;height:3px;border-radius:2px;background:#2B50FF;vertical-align:middle;margin-right:10px;"></span>Milvago</td></tr>
<tr><td style="background:#FFFFFF;border:1px solid #DCE4EE;border-radius:6px;padding:36px 40px;font-size:15px;line-height:1.6;color:#4D596B;">
<#nested>
</td></tr>
<tr><td style="padding:16px 4px 0;font-size:12px;line-height:1.6;color:#647083;"><#if sentTo?has_content>${msg("mvEmailFooter", sentTo)}<#else>Milvago</#if></td></tr>
</table>
</td></tr>
</table>
</body>
</html>
</#macro>

<#-- One message with one action: what the e-mail is about, its button, how long the link
     lasts, and the link itself for clients that do not show buttons. -->
<#macro action eyebrow title intro label link expiry>
<p style="margin:0 0 12px;font-size:11px;font-weight:700;letter-spacing:1.4px;text-transform:uppercase;color:#1F3FE6;">${eyebrow}</p>
<h1 style="margin:0 0 16px;font-size:26px;line-height:1.2;font-weight:600;letter-spacing:-0.5px;color:#172033;">${title}</h1>
<p style="margin:0 0 24px;">${intro}</p>
<p style="margin:0 0 24px;"><a href="${link}" style="display:inline-block;background:#2B50FF;color:#FFFFFF;font-size:15px;font-weight:600;text-decoration:none;padding:13px 22px;border-radius:4px;">${label}</a></p>
<p style="margin:0 0 20px;font-size:13px;color:#647083;">${expiry}</p>
<p style="margin:0;padding-top:14px;border-top:1px solid #DCE4EE;font-size:12px;color:#647083;">${msg("mvEmailLinkFallback")}<br><a href="${link}" style="color:#1F3FE6;word-break:break-all;">${link}</a></p>
</#macro>
