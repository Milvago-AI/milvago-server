<#ftl output_format="plainText">
${msg("mvVerifyEmailTitle")}

${msg("mvVerifyEmailIntro", (user.email)!"")}

${msg("mvVerifyEmailAction")}
${link}

${msg("mvVerifyEmailExpiry", linkExpirationFormatter(linkExpiration))}

--
Milvago
