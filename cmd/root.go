package cmd

import (
	"crypto/tls"
	"github.com/luastan/keytest/apiKeys"
	"github.com/luastan/keytest/kt"
	"github.com/luastan/keytest/logger"
	"github.com/spf13/cobra"
	"net/http"
	"net/url"
	"os"
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "keytest",
	Short: "Find and test API keys",
	Long: `Keytest will first help you finding API keys on static files (perfect for
mobile app analysis) and from HTTP traffic acting as a proxy.

Once you have your hands on the API keys, kt tests them and generates POCs
as well as a pricing chart.

API providers usually provide ways of limiting the usage of such keys to 
prevent abuses. Take the following example from google's documentation on API
security best practices:
 - https://developers.google.com/maps/api-security-best-practices#application-restriction`,
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

var (
	upstreamProxy  *string
	markdownOutput *string
)

func init() {
	// Workers
	kt.Workers = rootCmd.PersistentFlags().IntP("workers", "w", 100, "Number workers to use (simultaneous files opened)")

	// Debug mode
	kt.Debug = rootCmd.PersistentFlags().BoolP("test", "t", false, "Asume the key is vulnerable to everything and print the results.")

	// Markdown output
	markdownOutput = rootCmd.PersistentFlags().StringP("md", "o", "", "File to save the results in markdown")

	// Upstream proxy management
	upstreamProxy = rootCmd.PersistentFlags().StringP("upstream-proxy", "u", "", "Upstream proxy to use when making requests")

	kt.Client = http.Client{}
	kt.Client.Transport = &http.Transport{}
	if len(*upstreamProxy) > 0 {

		proxyURL, err := url.Parse(*upstreamProxy)
		if err != nil {
			logger.ErrorLogger.Fatalln("Unable to parse the upstream proxy URL")
		}

		kt.Client.Transport = &http.Transport{
			Proxy:           http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
	} else {
		kt.Client.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
	}

	// Register API key patterns

	kt.RegisterLoader(apiKeys.RegisterKeys)
	kt.LoadApiPatterns()
}
