<#import "template.ftl" as layout>
<#-- The console sends this e-mail only to invite a member. Without a password to choose,
     the invitation signs in with the organization's Google or Microsoft account. -->
<#assign direct = !(requiredActions?? && requiredActions?seq_contains("UPDATE_PASSWORD"))>
<@layout.emailLayout>
<@layout.action eyebrow=msg("mvInviteEyebrow") title=msg("mvInviteTitle") intro=msg(direct?then("mvInviteDirectIntro", "mvInviteIntro"), (user.email)!"") label=msg(direct?then("mvInviteDirectAction", "mvInviteAction")) link=link expiry=msg("mvInviteExpiry", linkExpirationFormatter(linkExpiration))/>
</@layout.emailLayout>
