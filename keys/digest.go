package keys

import (
	"github.com/luastan/keytest/kt"
	"github.com/luastan/keytest/logger"
	"sync"
)

const (
	foundApiKeyBuffer = 10
)

// FindKeys consumes a channel with *Lines and produces FoundApiKeys
func FindKeys(lines <-chan *Line) <-chan FoundAPIKey {
	ch := make(chan FoundAPIKey, foundApiKeyBuffer)
	go func() {
		defer close(ch)
		for line := range lines {
			// Búsqueda de la(s) clave(s) de API
			found := FindEveryKey(line)

			// Envío por el canal de encontradas
			for _, foundAPIKey := range found {
				ch <- foundAPIKey
			}
		}
	}()
	return ch
}

// FindEveryKey returns every key matching any defined KeyType
func FindEveryKey(line *Line) []FoundAPIKey {
	var found []FoundAPIKey
	for _, keyType := range KeyTypes {
		found = append(found, keyType.FindEveryKey(line)...)
	}
	return found
}

// FindEveryKey returns every key matching the KeyType on that line
func (kt KeyType) FindEveryKey(line *Line) []FoundAPIKey {
	var found []FoundAPIKey
	for _, key := range kt.Re.FindAllString(line.Content, -1) {
		found = append(found, FoundAPIKey{
			Key:      key,
			KeyType:  kt,
			Location: line.Location,
		})
	}
	return found
}

// UniqueKeys filters incoming FoundAPIKeys. Only forwards unique not already
// found API keys
func UniqueKeys(keys <-chan FoundAPIKey) <-chan FoundAPIKey {
	ch := make(chan FoundAPIKey)
	go func() {
		defer close(ch)
		alreadyFound := make(map[string]bool)
		for key := range keys {
			if !alreadyFound[key.Key] {
				alreadyFound[key.Key] = true
				ch <- key
			}
		}
	}()
	return ch
}

// FindVulns checks every endpoint for a given key. If no services/endpoints
// are vulnerable, nothing is sent through the KeyVulns channel
func FindVulns(keys <-chan FoundAPIKey) <-chan KeyVulns {
	ch := make(chan KeyVulns)
	go func() {
		defer close(ch)
		var wg sync.WaitGroup
		for i := 0; i < *kt.Workers; i++ {
			wg.Add(1)
			go func(wg *sync.WaitGroup, keys <-chan FoundAPIKey) {
				for key := range keys {
					vulnerableEndpoints, err := key.VulnerableEndpoints()
					if err != nil {
						logger.ErrorLogger.Println(err.Error())
					} else if len(vulnerableEndpoints) > 0 {
						ch <- KeyVulns{FoundAPIKey: key, VulnerableEndpoints: vulnerableEndpoints}
					}
				}
				wg.Done()
			}(&wg, keys)
		}
		wg.Wait()
	}()
	return ch
}
