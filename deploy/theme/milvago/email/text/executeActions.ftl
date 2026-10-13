<#ftl output_format="plainText">
<#-- The console sends this e-mail only to invite a member. Without a password to choose,
     the invitation signs in with the organization's Google or Microsoft account. -->
<#assign direct = !(requiredActions?? && requiredActions?seq_contains("UPDATE_PASSWORD"))>
${msg("mvInviteTitle")}

${msg(direct?then("mvInviteDirectIntro", "mvInviteIntro"), (user.email)!"")}

${msg(direct?then("mvInviteDirectAction", "mvInviteAction"))}
${link}

${msg("mvInviteExpiry", linkExpirationFormatter(linkExpiration))}

--
Milvago
