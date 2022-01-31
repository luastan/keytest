package keys

import (
	"github.com/luastan/keytest/kt"
	"github.com/luastan/keytest/logger"
	"io"
	"regexp"
	"sync"
)

type KeyType struct {
	Name      string
	Endpoints []KeyEndpoint
	Re        *regexp.Regexp
	Help      string
}

type KeyEndpoint struct {
	Name    string
	Pricing string
	Check   KeyCheck
}

type Location struct {
	File string
	Line int
}

type Line struct {
	Content  string
	Location *Location
}

type FoundAPIKey struct {
	Key      string
	KeyType  *KeyType
	Location *Location
}

type InputHandle struct {
	File   string
	Reader io.Reader
}

type KeyCheck interface {
	Poc(key FoundAPIKey, endpoint KeyEndpoint) (string, error)
	IsVulnerable(key FoundAPIKey, endpoint KeyEndpoint) (bool, error)
}

type KeyVulns struct {
	FoundAPIKey         FoundAPIKey
	VulnerableEndpoints []KeyEndpoint
}

// VulnerableEndpoints returns a list of the services the key is vulnerable to
func (k FoundAPIKey) VulnerableEndpoints() ([]KeyEndpoint, error) {
	// TODO probably this method should be moved
	var (
		mu        = &sync.Mutex{}
		endpoints = make([]KeyEndpoint, 0)
		wg        sync.WaitGroup
	)

	for _, endpoint := range k.KeyType.Endpoints {
		wg.Add(1)
		go func(endpoint KeyEndpoint) {
			defer wg.Done()
			var (
				isVulnerable bool
				err          error = nil
			)
			if !*kt.Debug { // Debug mode assumes every key is vulnerable to everything
				isVulnerable, err = endpoint.Check.IsVulnerable(k, endpoint)
			} else {
				isVulnerable = true
			}

			if err != nil {
				logger.ErrorLogger.Println(err.Error())
			}

			if isVulnerable {
				mu.Lock()
				endpoints = append(endpoints, endpoint)
				mu.Unlock()
			}
		}(endpoint)
	}

	wg.Wait()
	return endpoints, nil
}
