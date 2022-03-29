package apiKeys

import (
	"fmt"
	"github.com/luastan/keytest/keys"
	"github.com/luastan/keytest/kt"
	"net/http"
	"regexp"
	"strings"
)

var (

	// Defining it here since it can work with different keys
	fcmKeyEndpoint = keys.KeyEndpoint{
		// https://abss.me/posts/fcm-takeover/
		Name:    "Firebase Cloud Messaging Service Takeover",
		Pricing: "Free, but vulnerable to FCM Service Takeover",
		Check: keys.CustomRequestCheck{
			Data: map[string]interface{}{
				"URL": "https://fcm.googleapis.com/fcm/send",
			},
			CheckFactory: func(c keys.CustomRequestCheck, key keys.FoundAPIKey, endpoint keys.KeyEndpoint) (bool, error) {
				// Check is relatively simple. Issue a POST request with the
				// key in the authorization header. A 200 OK response means the
				// key is vulnerable.
				req, err := http.NewRequest(
					http.MethodPost,
					c.Data["URL"].(string),
					// Invalid registration_ids do translate into a 200 OK response.
					// If the registration_id exists a notification could be sent,
					// which would be a kinda destructive check, so is better to use
					// something that is unlikely to exist
					strings.NewReader("{\"registration_ids\":[\"XYZ\"]}"),
				)
				if err != nil {
					return false, err
				}
				req.Header.Add("Authorization", fmt.Sprintf("key=%s", key.Key))
				req.Header.Add("Content-Type", "application/json")
				res, err := kt.Client.Do(req)
				if err != nil {
					return false, err
				}
				return res.StatusCode == http.StatusOK, nil
			},
			PocFactory: func(c keys.CustomRequestCheck, key keys.FoundAPIKey, endpoint keys.KeyEndpoint) (string, error) {
				return fmt.Sprintf(`curl --header "Authorization: key=%s" \
     --header Content-Type:"application/json" \
     %s \
     -d "{\"registration_ids\":[\"XYZ\"]}"`, key.Key, c.Data["URL"].(string)), nil
			},
		},
	}

	GoogleKeys = []keys.KeyType{
		{
			Name: "Firebase Cloud Messaging server Key",
			Re:   regexp.MustCompile(`AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}`),
			Help: "Can be used to send push notifications to users. More info at:\n - https://abss.me/posts/fcm-takeover/",
			Endpoints: []keys.KeyEndpoint{

				// Common Endpoints
				fcmKeyEndpoint,
			},
		},
		{
			Name: "Google API Key",
			Re:   regexp.MustCompile(`AIza[0-9A-Za-z-_]{35}`),
			Help: "Google API keys. Multiple uses. More info at:\n - https://github.com/streaak/keyhacks#google-maps-api-key",
			Endpoints: []keys.KeyEndpoint{

				// Common Endpoints
				fcmKeyEndpoint,

				// _Specific to this key_ Endpoints
				{
					Name:    "Google Maps Custom Search API",
					Pricing: "$5 per 1000 requests",
					Check:   keys.GetContainsError{ErrorString: "errors", U: "https://www.googleapis.com/customsearch/v1?cx=017576662512468239146:omuauf_lfve&q=lectures&key={{ .Key }}"},
				},
				{
					Name:    "Google Maps Staticmap API",
					Pricing: "$2 per 1000 requests",
					Check:   keys.GetStatusCheck{U: "https://maps.googleapis.com/maps/api/staticmap?center=45%2C10&zoom=7&size=400x400&key={{ .Key }}", StatusCode: 200},
				},
				{
					Name:    "Google Maps Streetview API",
					Pricing: "$7 per 1000 requests",
					Check:   keys.GetStatusCheck{U: "https://maps.googleapis.com/maps/api/streetview?size=400x400&location=40.720032,-73.988354&fov=90&heading=235&pitch=10&key={{ .Key }}", StatusCode: 200},
				},
				{
					Name:    "Google Maps Find Place From Text API",
					Pricing: "$17 per 1000 element",
					Check:   keys.GetContainsError{ErrorString: "error_message", U: "https://maps.googleapis.com/maps/api/place/findplacefromtext/json?input=Museum%20of%20Contemporary%20Art%20Australia&inputtype=textquery&fields=photos,formatted_address,name,rating,opening_hours,geometry&key={{ .Key }}"},
				},
				{
					Name:    "Google Maps Embed (Basic) API",
					Pricing: "Free",
					Check:   keys.GetStatusCheck{StatusCode: 200, U: "https://www.google.com/maps/embed/v1/place?q=Seattle&key={{ .Key }}"},
				},
				{
					Name:    "Google Maps Embed (Advanced) API",
					Pricing: "Free",
					Check:   keys.GetStatusCheck{StatusCode: 200, U: "https://www.google.com/maps/embed/v1/search?q=record+stores+in+Seattle&key={{ .Key }}"},
				},
				{
					Name:    "Google Maps Directions API",
					Pricing: "$5-$10 per 1000 requests",
					Check:   keys.GetContainsError{ErrorString: "error_message", U: "https://maps.googleapis.com/maps/api/directions/json?origin=Disneyland&destination=Universal+Studios+Hollywood4&key={{ .Key }}"},
				},
				{
					Name:    "Google Maps Geocode API",
					Pricing: "$5 per 1000 requests",
					Check:   keys.GetContainsError{ErrorString: "error_message", U: "https://maps.googleapis.com/maps/api/geocode/json?latlng=40,30&key={{ .Key }}"},
				},
				{
					Name:    "Google Maps Distance Matrix API",
					Pricing: "$5-$10 per 1000 elements",
					Check:   keys.GetContainsError{ErrorString: "error_message", U: "https://maps.googleapis.com/maps/api/distancematrix/json?units=imperial&origins=40.6655101,-73.89188969999998&destinations=40.6905615%2C-73.9976592%7C40.6905615%2C-73.9976592%7C40.6905615%2C-73.9976592%7C40.6905615%2C-73.9976592%7C40.6905615%2C-73.9976592%7C40.6905615%2C-73.9976592%7C40.659569%2C-73.933783%7C40.729029%2C-73.851524%7C40.6860072%2C-73.6334271%7C40.598566%2C-73.7527626%7C40.659569%2C-73.933783%7C40.729029%2C-73.851524%7C40.6860072%2C-73.6334271%7C40.598566%2C-73.7527626&key={{ .Key }}"},
				},
				{
					Name:    "Google Maps Find Place From Text API",
					Pricing: "$17 per 1000 elements",
					Check:   keys.GetContainsError{ErrorString: "error_message", U: "https://maps.googleapis.com/maps/api/place/findplacefromtext/json?input=Museum%20of%20Contemporary%20Art%20Australia&inputtype=textquery&fields=photos,formatted_address,name,rating,opening_hours,geometry&key={{ .Key }}"},
				},
				{
					Name:    "Google Maps Autocomplete API",
					Pricing: "$2.83 per 1000 requests / $17 per 1000 requests (Autocomplete Per Session)",
					Check:   keys.GetContainsError{ErrorString: "error_message", U: "https://maps.googleapis.com/maps/api/place/autocomplete/json?input=Bingh&types=%28cities%29&key={{ .Key }}"},
				},
				{
					Name:    "Google Maps Elevation API",
					Pricing: "$5 per 1000 requests",
					Check:   keys.GetContainsError{ErrorString: "error_message", U: "https://maps.googleapis.com/maps/api/elevation/json?locations=39.7391536,-104.9847034&key={{ .Key }}"},
				},
				{
					Name:    "Google Maps Timezone API",
					Pricing: "$5 per 1000 requests",
					Check:   keys.GetContainsError{ErrorString: "errorMessage", U: "https://maps.googleapis.com/maps/api/timezone/json?location=39.6034810,-119.6822510&timestamp=1331161200&key={{ .Key }}"},
				},
				{
					Name:    "Google Maps Nearest Roads API",
					Pricing: "$10 per 1000 requests",
					Check:   keys.GetContainsError{ErrorString: "error", U: "https://roads.googleapis.com/v1/nearestRoads?points=60.170880,24.942795|60.170879,24.942796|60.170877,24.942796&key={{ .Key }}"},
				},
				{
					Name:    "Google Maps Geolocation API",
					Pricing: "$5 per 1000 requests",
					Check:   keys.PostContainsError{ErrorString: "error", ContentType: "application/json", Body: "{\"considerIp\": \"true\"}", U: "https://www.googleapis.com/geolocation/v1/geolocate?key={{ .Key }}"},
				},
				{
					Name:    "Google Maps Route to Traveled API",
					Pricing: "$10 per 1000 requests",
					Check:   keys.GetContainsError{ErrorString: "error", U: "https://roads.googleapis.com/v1/snapToRoads?path=-35.27801,149.12958|-35.28032,149.12907&interpolate=true&key={{ .Key }}"},
				},
				{
					Name:    "Google Maps Speed Limit-Roads API",
					Pricing: "$20 per 1000 requests",
					Check:   keys.GetContainsError{ErrorString: "error", U: "https://roads.googleapis.com/v1/speedLimits?path=38.75807927603043,-9.03741754643809&key={{ .Key }}"},
				},
				{
					Name:    "Google Maps Speed Limit-Roads API",
					Pricing: "$20 per 1000 requests",
					Check:   keys.GetContainsError{ErrorString: "error", U: "https://roads.googleapis.com/v1/speedLimits?path=38.75807927603043,-9.03741754643809&key={{ .Key }}"},
				},
				{
					Name:    "Google Maps Place Details API",
					Pricing: "$17 per 1000 requests",
					Check:   keys.GetContainsError{ErrorString: "error_message", U: "https://maps.googleapis.com/maps/api/place/details/json?place_id=ChIJN1t_tDeuEmsRUsoyG83frY4&fields=name,rating,formatted_phone_number&key={{ .Key }}"},
				},
				{
					Name:    "Google Maps Nearby Search-Places API",
					Pricing: "$32 per 1000 requests",
					Check:   keys.GetContainsError{ErrorString: "error_message", U: "https://maps.googleapis.com/maps/api/place/nearbysearch/json?location=-33.8670522,151.1957362&radius=100&types=food&name=harbour&key={{ .Key }}"},
				},
				{
					Name:    "Google Maps Text Search-Places API",
					Pricing: "$32 per 1000 requests",
					Check:   keys.GetContainsError{ErrorString: "error_message", U: "https://maps.googleapis.com/maps/api/place/textsearch/json?query=restaurants+in+Sydney&key={{ .Key }}"},
				},
				{
					Name:    "Google Maps Places Photo API",
					Pricing: "$7 per 1000 requests",
					Check:   keys.GetStatusCheck{StatusCode: 302, U: "https://maps.googleapis.com/maps/api/place/photo?maxwidth=400&photoreference=CnRtAAAATLZNl354RwP_9UKbQ_5Psy40texXePv4oAlgP4qNEkdIrkyse7rPXYGd9D_Uj1rVsQdWT4oRz4QrYAJNpFX7rzqqMlZw2h2E2y5IKMUZ7ouD_SlcHxYq1yL4KbKUv3qtWgTK0A6QbGh87GB3sscrHRIQiG2RrmU_jF4tENr9wGS_YxoUSSDrYjWmrNfeEHSGSc3FyhNLlBU&key={{ .Key }}"},
				},

				//{
				//	Name:    "",
				//	Pricing: "",
				//	Check:   postContainsError{errorString: "", contentType: "", body: "", u: "{{ .Key }}"},
				//},
				//
				//{
				//	Name:    "",
				//	Pricing: "",
				//	Check:   keys.GetContainsError{errorString: "", u: "{{ .Key }}"},
				//},
				//{
				//	Name:    "",
				//	Pricing: "",
				//	Check:   keys.GetStatusCheck{statusCode: 200, u: "{{ .Key }}"},
				//},
			},
		},
	}
)
