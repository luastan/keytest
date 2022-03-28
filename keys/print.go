package keys

import (
	"fmt"
	"github.com/luastan/keytest/logger"
	"io"
	"os"
	"sync"
	"text/template"
)

func (k FoundAPIKey) String() string {
	return fmt.Sprintf("%s\t%s\t%s:%d", k.Key, k.KeyType.Name, k.Location.File, k.Location.Line)
}

// LogResults Launch a Goroutine that consumes FoundAPIKeys and prints them
// to stdout
func LogResults(wg *sync.WaitGroup, results <-chan FoundAPIKey, silent bool) {
	wg.Add(1)
	go func() {
		defer wg.Done()
		for result := range results {
			if silent {
				fmt.Println(result.Key)
			} else {
				fmt.Println(result)
			}
		}

	}()
}

const consoleVulnerableTemplate = `[+] {{ .FoundAPIKey.KeyType.Name }} - {{ .FoundAPIKey.Key }} {{ $fk := .FoundAPIKey }}
{{ range $endpoint := .VulnerableEndpoints }} 
  - {{ .Name }}
  - Price: {{ .Pricing }}
  - POC: {{ .Check.Poc $fk $endpoint }}
{{end}}

`

const markdownVulnerablesTemplate = `{{ range . }}{{ $fk := .FoundAPIKey }}
- **{{ $fk.KeyType.Name }}**
  - ` + "_{{ $fk.Key }}_" + `
  - **Location:** {{ $fk.Location.File }} (line {{ $fk.Location.Line }})

{{ range $endpoint := .VulnerableEndpoints }}
  - **{{ .Name }}:**
    - **Price:** {{ .Pricing }}
    - **POC:**
` + "```" + `
{{ .Check.Poc $fk $endpoint }}
` + "```" + `

{{end}}
| Vulnerable API | Pricing |
|---|---|{{ range $endpoint := .VulnerableEndpoints }}
| {{ .Name }} | {{ .Pricing }} |{{end}}
{{end}}
`

func LogToMarkdown(wg *sync.WaitGroup, results <-chan KeyVulns, markdownWriter io.Writer) error {
	tmpl, err := template.New("results-md").Parse(markdownVulnerablesTemplate)
	if err != nil {
		return err
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		err = tmpl.Execute(markdownWriter, results)
		if err != nil {
			logger.ErrorLogger.Println(err.Error())
		}
	}()

	return nil
}

func LogVulnerableKeys(wg *sync.WaitGroup, results <-chan KeyVulns) (<-chan KeyVulns, error) {
	tmpl, err := template.New("results").Parse(consoleVulnerableTemplate)
	if err != nil {
		return nil, err
	}
	ch := make(chan KeyVulns, 10)
	wg.Add(1)
	go func() {
		defer wg.Done()
		for result := range results {
			err = tmpl.Execute(os.Stdout, result)
			if err != nil {
				logger.ErrorLogger.Println(err.Error())
			}
			ch <- result
		}
		close(ch)
	}()

	return ch, nil
}
