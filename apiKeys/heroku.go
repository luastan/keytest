package apiKeys

import (
	"fmt"
	"github.com/luastan/keytest/keys"
	"github.com/luastan/keytest/kt"
	"net/http"
	"regexp"
)

func AddHerokuKeys() {
	keys.AddKeyTypes(HerokuKeys)
}

var (
	HerokuKeys = []keys.KeyType{
		{
			Name: "Heroku Authorization Token",
			Re:   regexp.MustCompile(`[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}`),
			Help: "Create apps and interact with the infrastructure as a privileged user",
			Endpoints: []keys.KeyEndpoint{
				{
					Name:    "Heroku Platform API",
					Pricing: "Interaction with the platform as an admin",
					Check: keys.CustomRequestCheck{
						Data: map[string]interface{}{
							"URL": "https://api.heroku.com/apps",
						},
						// Key is vulnerable if the status code is 200
						CheckFactory: func(c keys.CustomRequestCheck, key keys.FoundAPIKey, endpoint keys.KeyEndpoint) (bool, error) {
							req, err := http.NewRequest(http.MethodGet, c.Data["URL"].(string), nil)
							if err != nil {
								return false, err
							}

							req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", key.Key))
							req.Header.Add("Accept", "application/vnd.heroku+json; version=3")

							res, err := kt.Client.Do(req)
							if err != nil {
								return false, err
							}

							return res.StatusCode == http.StatusOK, nil
						},
						PocFactory: func(c keys.CustomRequestCheck, key keys.FoundAPIKey, endpoint keys.KeyEndpoint) (string, error) {
							return fmt.Sprintf(`curl --header "Authorization: Bearer %s" \
     --header "Accept: application/vnd.heroku+json; version=3" \
     %s`, key.Key, c.Data["URL"].(string)), nil
						},
					},
				},
			},
		},
	}
)
