package cmd

import (
	"github.com/spf13/cobra"
	"keytest/keys"
	"keytest/logger"
	"os"
	"sync"
)

// checkCmd represents the check command
var checkCmd = &cobra.Command{
	Use:   "check",
	Short: "Check the scope for API keys",
	Long: `
Use every single provided API against a set of defined endpoints to check
whether or not its use is properly limited.`,
	Run: func(cmd *cobra.Command, args []string) {

		var inputHandles <-chan keys.InputHandle

		if len(args) > 0 {
			paths := keys.Files(args)
			inputHandles = keys.PathsToInputHandles(paths)
		} else {
			inputHandles = keys.InputHandlesFromStdin()
		}

		lines := keys.ReadersToLines(inputHandles)
		found := keys.FindKeys(lines)
		foundUnique := keys.UniqueKeys(found)
		vulns := keys.FindVulns(foundUnique)
		var wg sync.WaitGroup

		vulns, err := keys.LogVulnerableKeys(&wg, vulns)
		if err != nil {
			logger.ErrorLogger.Fatalln(err.Error())
			return
		}
		if len(*markdownOutput) > 0 {
			f, err := os.Create(*markdownOutput)
			if err != nil {
				logger.ErrorLogger.Fatalln(err.Error())
			}
			err = keys.LogToMarkdown(&wg, vulns, f)
		} else {
			for range vulns {
			}
		}

		wg.Wait()

	},
}

func init() {
	rootCmd.AddCommand(checkCmd)
}
