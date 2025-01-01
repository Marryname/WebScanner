package main

import (
	"fmt"

	"github.com/spf13/cobra"
)

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "显示版本信息",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("GoSecScanner v%s\n", Version)
		fmt.Printf("构建时间: %s\n", BuildTime)
	},
}
