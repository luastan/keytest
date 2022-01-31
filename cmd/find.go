package cmd

import (
	"github.com/spf13/cobra"
	"keytest/keys"
	"sync"
)

// findCmd represents the find command
var findCmd = &cobra.Command{
	Use:   "find [DIRECTORY|FILE]...",
	Short: "Find API keys in files or from stdin",
	Long:  `Find API keys in files or from stdin.`,
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
		var wg sync.WaitGroup

		keys.LogResults(&wg, found, *silent)
		wg.Wait()
	},
}

var (
	maxDepth *int
	silent   *bool
)

func init() {
	rootCmd.AddCommand(findCmd)
	maxDepth = findCmd.Flags().IntP("depth", "d", -1, "Specify the depth to use when traversing directories. -1 is unlimited")
	silent = findCmd.Flags().BoolP("silent", "s", false, "Hide key types when outputing to stdout")

}
