package kt

import "net/http"

var (
	Client  http.Client
	Debug   *bool
	loaders []func()
)

func LoadApiPatterns() {
	for _, loader := range loaders {
		loader()
	}
}

func RegisterLoader(loader func()) {
	loaders = append(loaders, loader)
}
