<#import "template.ftl" as layout>
<@layout.emailLayout recipient=newEmail>
<@layout.action eyebrow=msg("mvVerifyEmailEyebrow") title=msg("mvUpdateEmailTitle") intro=msg("mvUpdateEmailIntro", newEmail) label=msg("mvUpdateEmailAction") link=link expiry=msg("mvVerifyEmailExpiry", linkExpirationFormatter(linkExpiration))/>
</@layout.emailLayout>
