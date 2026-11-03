package app

import (
	_ "embed"
	"github.com/jackc/pgx/v5"
	"go.yaml.in/yaml/v3"
	"net/http"
	"strings"
)

//go:embed ai_governance_controls.yaml
var aiGovernanceControls string

type aiGovernanceControl struct {
	ID         string `json:"id" yaml:"id"`
	Capability string `json:"capability" yaml:"capability"`
	Coverage   string `json:"coverage" yaml:"coverage"`
	Evidence   string `json:"evidence" yaml:"evidence"`
}
type aiGovernanceProfile struct {
	Version   int                   `json:"version" yaml:"version"`
	ID        string                `json:"id" yaml:"id"`
	Framework string                `json:"framework" yaml:"framework"`
	Source    string                `json:"source" yaml:"source"`
	Notice    string                `json:"notice" yaml:"notice"`
	Controls  []aiGovernanceControl `json:"controls" yaml:"controls"`
}

func (a *App) aiGovernanceFramework(w http.ResponseWriter, r *http.Request, tx pgx.Tx, s *Session) error {
	var profile aiGovernanceProfile
	decoder := yaml.NewDecoder(strings.NewReader(aiGovernanceControls))
	decoder.KnownFields(true)
	if err := decoder.Decode(&profile); err != nil {
		return err
	}
	reply(w, 200, profile)
	return nil
}
