<#import "template.ftl" as layout>
<@layout.emailLayout>
<@layout.action eyebrow=msg("mvResetEmailEyebrow") title=msg("mvResetEmailTitle") intro=msg("mvResetEmailIntro", (user.email)!"") label=msg("mvResetEmailAction") link=link expiry=msg("mvResetEmailExpiry", linkExpirationFormatter(linkExpiration))/>
</@layout.emailLayout>
