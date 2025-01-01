package main

import (
	"fmt"

	"github.com/spf13/cobra"
)

var (
	// Version 版本号，可以在编译时通过 -ldflags 设置
	Version = "v0.1.0"
	// BuildTime 构建时间，可以在编译时通过 -ldflags 设置
	BuildTime = "unknown"
)

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "显示版本信息",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("WebScanner %s\n", Version)
		fmt.Printf("构建时间: %s\n", BuildTime)
	},
}
