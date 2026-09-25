package app

import (
	"context"
	"encoding/json"
	"testing"
	"time"
)

// Un envoi accompagné d'un fichier laisse DEUX enregistrements sous la même corrélation :
// le fichier part chez le fournisseur dès qu'il est attaché, donc il est enregistré avant
// le texte. Les compteurs en annonçaient deux requêtes là où la console, depuis le
// 2026-09-15, n'affiche plus qu'une bulle — l'écran et le chiffre se contredisaient.
//
// Le critère n'est PAS la présence de noms de fichiers : quand leur remontée est
// désactivée, l'enregistrement d'attache n'en porte aucun. C'est un prompt à zéro
// caractère partageant sa corrélation avec un prompt porteur de texte.
func addAttachmentRecord(t *testing.T, f *observabilityFixture, subject, device string, at time.Time, correlation string, files []string) {
	t.Helper()
	names, e := json.Marshal(files)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = f.admin.Exec(context.Background(), `INSERT INTO shadow_events(organization_id,device_id,id,occurred_at,kind,provider,tool,source,action,policy_revision,characters,sensitivity,collaborator_id,conversation_id,correlation_id,files)
		VALUES($1,$2,gen_random_uuid(),$3,'prompt','claude.ai','chrome','browser','observed',1,0,'unknown',$4,'',$5,$6)`,
		f.org, device, at, subject, correlation, names); e != nil {
		t.Fatal(e)
	}
}

func TestAttachmentRecordCountsWithItsSend(t *testing.T) {
	base := time.Now().UTC().Add(-time.Hour)
	window := "?from=" + base.Add(-time.Minute).Format(time.RFC3339Nano) + "&to=" + base.Add(time.Minute).Format(time.RFC3339Nano)

	t.Run("a conversation announces one request per send, attachment included", func(t *testing.T) {
		f, subject, device := privacyFixture(t)
		// L'attache d'abord, le texte ensuite, sous la même corrélation : l'ordre réel.
		addAttachmentRecord(t, f, subject, device, base, "correlation-file", []string{"schema-synthetique.png"})
		addThreadEvent(t, f, subject, device, base.Add(time.Second), "prompt", "", "correlation-file", "observed", "Analyse ce document.")
		addThreadEvent(t, f, subject, device, base.Add(2*time.Second), "response", "", "correlation-file", "observed", "Réponse de test.")
		// Le même échange sans remontée des noms : l'enregistrement d'attache n'a pas de
		// fichiers, et doit quand même être reconnu.
		addAttachmentRecord(t, f, subject, device, base.Add(3*time.Second), "correlation-silent", nil)
		addThreadEvent(t, f, subject, device, base.Add(4*time.Second), "prompt", "", "correlation-silent", "observed", "Et celui-ci ?")

		items := readConversations(t, f, window)
		byKey := map[string]ConversationView{}
		for _, item := range items {
			byKey[item.Key] = item
		}
		with, ok := byKey["corr:correlation-file"]
		if !ok {
			t.Fatalf("exchange not grouped on its correlation: %v", byKey)
		}
		if with.Prompts != 1 || with.Responses != 1 {
			t.Fatalf("an attachment is part of its send, not a second one: %+v", with)
		}
		silent, ok := byKey["corr:correlation-silent"]
		if !ok {
			t.Fatalf("exchange not grouped on its correlation: %v", byKey)
		}
		if silent.Prompts != 1 {
			t.Fatalf("file names are off: the attachment record carries none and must still count with its send: %+v", silent)
		}
	})

	t.Run("an attachment with no send that follows keeps its own count", func(t *testing.T) {
		f, subject, device := privacyFixture(t)
		// Attaché puis abandonné : il n'y a pas d'envoi auquel le rattacher, et cet
		// enregistrement décrit alors exactement ce qui s'est passé.
		addAttachmentRecord(t, f, subject, device, base, "correlation-lonely", []string{"schema-synthetique.png"})
		items := readConversations(t, f, window)
		if len(items) != 1 || items[0].Prompts != 1 {
			t.Fatalf("a lone attachment must remain visible and counted: %+v", items)
		}
	})

	t.Run("the 24-hour counters stay additive and drop the attachment record", func(t *testing.T) {
		f, subject, device := privacyFixture(t)
		recent := time.Now().UTC().Add(-time.Minute)
		addAttachmentRecord(t, f, subject, device, recent, "correlation-metrics", []string{"schema-synthetique.png"})
		addThreadEvent(t, f, subject, device, recent.Add(time.Second), "prompt", "", "correlation-metrics", "observed", "Analyse ce document.")
		addThreadEvent(t, f, subject, device, recent.Add(2*time.Second), "response", "", "correlation-metrics", "observed", "Réponse de test.")
		addThreadEvent(t, f, subject, device, recent.Add(3*time.Second), "navigation", "", "correlation-metrics", "observed", "")

		// La route est gouvernée par MILVAGO_SHADOW_METRICS, que le harnais laisse fermée.
		f.a.config.ShadowMetrics = true
		w := f.call("GET", "/api/shadow/metrics", nil, "")
		requireHTTP(t, w, 200)
		var out struct {
			Events      int `json:"events"`
			Prompts     int `json:"prompts"`
			Responses   int `json:"responses"`
			Navigations int `json:"navigations"`
		}
		if e := json.Unmarshal(w.Body.Bytes(), &out); e != nil {
			t.Fatal(e)
		}
		if out.Prompts != 1 || out.Responses != 1 || out.Navigations != 1 {
			t.Fatalf("one send, one request: %+v", out)
		}
		// Le total reste la somme des natures : écarter l'enregistrement d'un compteur et
		// pas de l'autre ferait mentir la page qui les additionne.
		if out.Events != out.Prompts+out.Responses+out.Navigations {
			t.Fatalf("counters no longer add up: %+v", out)
		}
	})
}
