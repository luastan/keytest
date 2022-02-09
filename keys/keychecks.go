package keys

import (
	"bytes"
	"github.com/luastan/keytest/kt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"text/template"
)

func responseBodyString(res *http.Response) string {
	b, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return ""
	}
	return string(b)
}

type urlTemplate interface {
	getURLTemplate() string
}

// templatePoc simply fills the url template with the FoundAPIKey attributes
func templatePoc(check urlTemplate, key FoundAPIKey) (string, error) {
	tmpl, err := template.New("URL").Parse(check.getURLTemplate())
	if err != nil {
		return "", err
	}

	var tmplOutput bytes.Buffer
	if err := tmpl.Execute(&tmplOutput, key); err != nil {
		return "", err
	}

	u, err := url.Parse(tmplOutput.String())
	if err != nil {
		return "", err
	}

	return u.String(), nil
}

type curlablePOC interface {
	getContentType() string
	getBody() string
	getURLTemplate() string
}

const curlTmpl = `curl -s -k -i -X POST -H "Content-Type: {{ .contentType }}" --data-binary $'{{ .body }}' $'{{ .u }}'`

// getCurlPostPOC outputs a curl command as a POC for the vulnerability
func getCurlPostPOC(check curlablePOC, key FoundAPIKey) (string, error) {
	uTmpl, err := template.New("URL").Parse(check.getURLTemplate())
	if err != nil {
		return "", err
	}
	curlTmpl, err := template.New("CURL_POC").Parse(curlTmpl)
	if err != nil {
		return "", err
	}

	var (
		uBuffer    bytes.Buffer
		curlBuffer bytes.Buffer
	)

	if err := uTmpl.Execute(&uBuffer, key); err != nil {
		return "", err
	}
	u, err := url.Parse(uBuffer.String())
	if err != nil {
		return "", err
	}

	curlData := map[string]interface{}{
		"u":           u.String(),
		"contentType": check.getContentType(),
		"body":        check.getBody(),
	}

	if err := curlTmpl.Execute(&curlBuffer, curlData); err != nil {
		return "", err
	}

	return curlBuffer.String(), nil
}

/*

	Check via status code response to GET request

*/
type GetStatusCheck struct {
	U          string
	StatusCode int
}

func (check GetStatusCheck) getURLTemplate() string {
	return check.U
}

func (check GetStatusCheck) Poc(key FoundAPIKey, endpoint KeyEndpoint) (string, error) {
	return templatePoc(check, key)
}

func (check GetStatusCheck) IsVulnerable(key FoundAPIKey, endpoint KeyEndpoint) (bool, error) {
	u, err := check.Poc(key, endpoint)
	if err != nil {
		return false, err
	}

	resp, err := kt.Client.Get(u)
	if err != nil {
		return false, err
	}

	return resp.StatusCode == check.StatusCode, nil
}

/*

	Check via error string in response to GET request

*/

type GetContainsError struct {
	U           string
	ErrorString string
}

func (check GetContainsError) getURLTemplate() string {
	return check.U
}

func (check GetContainsError) Poc(key FoundAPIKey, endpoint KeyEndpoint) (string, error) {
	return templatePoc(check, key)
}

func (check GetContainsError) IsVulnerable(key FoundAPIKey, endpoint KeyEndpoint) (bool, error) {
	u, err := check.Poc(key, endpoint)
	if err != nil {
		return false, err
	}

	resp, err := kt.Client.Get(u)
	rawBody := responseBodyString(resp)

	return !strings.Contains(rawBody, check.ErrorString), nil
}

/*

	Check via error string in response to GET request

*/

type PostContainsError struct {
	U           string
	Body        string
	ContentType string
	ErrorString string
}

func (check PostContainsError) getContentType() string {
	return check.ContentType
}

func (check PostContainsError) getBody() string {
	return check.Body
}

func (check PostContainsError) getURLTemplate() string {
	return check.U
}

func (check PostContainsError) Poc(key FoundAPIKey, endpoint KeyEndpoint) (string, error) {
	return getCurlPostPOC(check, key)
}

func (check PostContainsError) IsVulnerable(key FoundAPIKey, endpoint KeyEndpoint) (bool, error) {
	u, err := templatePoc(check, key)
	if err != nil {
		return false, err
	}

	resp, err := kt.Client.Post(u, check.getContentType(), strings.NewReader(check.getBody()))

	rawBody := responseBodyString(resp)

	return !strings.Contains(rawBody, check.ErrorString), nil
}

/*

	Very custom stuff

*/

type CustomRequestCheck struct {
	Data         map[string]interface{}
	PocFactory   func(c CustomRequestCheck, key FoundAPIKey, endpoint KeyEndpoint) (string, error)
	CheckFactory func(c CustomRequestCheck, key FoundAPIKey, endpoint KeyEndpoint) (bool, error)
}

func (c CustomRequestCheck) Poc(key FoundAPIKey, endpoint KeyEndpoint) (string, error) {
	return c.PocFactory(c, key, endpoint)
}

func (c CustomRequestCheck) IsVulnerable(key FoundAPIKey, endpoint KeyEndpoint) (bool, error) {
	return c.CheckFactory(c, key, endpoint)
}
