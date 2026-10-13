<#ftl output_format="plainText">
${msg("mvResetEmailTitle")}

${msg("mvResetEmailIntro", (user.email)!"")}

${msg("mvResetEmailAction")}
${link}

${msg("mvResetEmailExpiry", linkExpirationFormatter(linkExpiration))}

--
Milvago
