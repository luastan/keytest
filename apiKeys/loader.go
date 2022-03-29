package apiKeys

import "github.com/luastan/keytest/keys"

// RegisterKeys adds the different definitions on this package to the global
// list in order to be used.
func RegisterKeys() {
	keys.AddKeyTypes(GoogleKeys)
	keys.AddKeyTypes(HerokuKeys)
}
