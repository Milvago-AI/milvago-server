package app

import (
	"errors"
	"net/textproto"
	"strings"
	"testing"
)

func TestSetupSMTPFailure(t *testing.T) {
	rejected := setupSMTPFailure(smtpRecipientFailure(&textproto.Error{Code: 550, Msg: "5.1.1 No such recipient. For more information, go to https://example.test/help"}))
	if rejected.status != 502 || rejected.code != "smtp_recipient_unknown" || strings.Contains(rejected.message, "https://") {
		t.Fatalf("recipient refusal should give an actionable error without a cut-off help link: %#v", rejected)
	}
	otherStage := setupSMTPFailure(&textproto.Error{Code: 550, Msg: "5.1.1 No such recipient"})
	if otherStage.code != "smtp_failed" {
		t.Fatalf("only recipient refusals should identify the recipient: %#v", otherStage)
	}
	generic := setupSMTPFailure(errors.New(strings.Repeat("smtp unavailable ", 30)))
	if generic.code != "smtp_failed" || !strings.HasSuffix(generic.message, "...") || len([]rune(generic.message)) > 250 {
		t.Fatalf("other SMTP failures should remain bounded: %#v", generic)
	}
}
