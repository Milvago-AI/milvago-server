<#import "template.ftl" as layout>
<@layout.emailLayout>
<@layout.action eyebrow=msg("mvVerifyEmailEyebrow") title=msg("mvVerifyEmailTitle") intro=msg("mvVerifyEmailIntro", (user.email)!"") label=msg("mvVerifyEmailAction") link=link expiry=msg("mvVerifyEmailExpiry", linkExpirationFormatter(linkExpiration))/>
</@layout.emailLayout>
