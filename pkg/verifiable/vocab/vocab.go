package vocab

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html/template"
	"net/url"

	_ "embed"
)

//go:embed vocab.tmpl
var vocabTemplate string

// Term represents a definition of a term in a vocabulary.
type Term struct {
	Name        string
	Description string
	Usage       string
}

// Vocabulary represents a vocabulary of terms.
type Vocabulary struct {
	BaseURL url.URL
	Terms   []Term
}

// NewVocabulary creates a new Vocabulary instance.
func NewVocabulary(terms []Term, baseURL url.URL) *Vocabulary {
	return &Vocabulary{
		Terms:   terms,
		BaseURL: baseURL,
	}
}

// RenderWebpage renders the terms as a webpage using the embedded template.
func (v *Vocabulary) RenderWebpage() ([]byte, error) {
	tmpl, err := template.New("vocab").Parse(vocabTemplate)
	if err != nil {
		return nil, fmt.Errorf("failed to parse template: %w", err)
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, v); err != nil {
		return nil, fmt.Errorf("failed to execute template: %w", err)
	}

	return buf.Bytes(), nil
}

// RenderJSONLD renders the terms as a JSON-LD document.
func (v *Vocabulary) RenderJSONLD() ([]byte, error) {
	context := map[string]any{
		"id":   "@id",
		"type": "@type",
	}
	for _, term := range v.Terms {
		context[term.Name] = map[string]string{
			"@id":   fmt.Sprintf("%s#%s", v.BaseURL.String(), term.Name),
			"@type": "@id",
		}
	}

	jsonLd := map[string]any{
		"@context": context,
	}

	jsonData, err := json.MarshalIndent(jsonLd, "", "  ")
	if err != nil {
		return nil, err
	}

	return jsonData, nil
}
