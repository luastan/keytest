package keys

// https://github.com/ozguralp/gmapsapiscanner/blob/master/maps_api_scanner_python3.py

var (
	KeyTypes []KeyType
)

func AddKeyTypes(keyTypes []KeyType) {
	KeyTypes = append(KeyTypes, keyTypes...)
}

func init() {
	KeyTypes = []KeyType{}
}
