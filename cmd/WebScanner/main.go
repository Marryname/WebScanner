package main

import (
	"fmt"
	"os"

	"github.com/Marryname/WebScanner/pkg/logger"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	// 全局配置
	cfgFile     string
	logLevel    string
	logFile     string
	showVersion bool

	// 全局日志记录器
	log *logger.Logger
)

// rootCmd 表示基本命令
var rootCmd = &cobra.Command{
	Use:   "webscan",
	Short: "一个综合性的网络安全扫描工具",
	Long: `WebScanner 是一个功能完整的网络安全扫描工具，提供以下功能：
  - 端口扫描
  - 子域名发现
  - CDN识别
  - 存活探测
  - 服务识别
  - 漏洞扫描`,
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		// 初始化日志
		initLogger()
	},
}

func init() {
	cobra.OnInitialize(initConfig)

	// 全局标志
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "配置文件路径")
	rootCmd.PersistentFlags().StringVar(&logLevel, "log-level", "info", "日志级别 (debug|info|warn|error)")
	rootCmd.PersistentFlags().StringVar(&logFile, "log-file", "", "日志文件路径")
	rootCmd.PersistentFlags().BoolVarP(&showVersion, "version", "v", false, "显示版本信息")

	// 添加子命令
	rootCmd.AddCommand(scanCmd)
	rootCmd.AddCommand(versionCmd)
}

// initConfig 读取配置文件和环境变量
func initConfig() {
	if cfgFile != "" {
		viper.SetConfigFile(cfgFile)
	} else {
		// 搜索配置文件的默认位置
		viper.AddConfigPath(".")
		viper.AddConfigPath("$HOME/.webscan")
		viper.AddConfigPath("/etc/webscan")
		viper.SetConfigName("config")
	}

	viper.AutomaticEnv()

	if err := viper.ReadInConfig(); err == nil {
		fmt.Printf("使用配置文件: %s\n", viper.ConfigFileUsed())
	}
}

// initLogger 初始化日志记录器
func initLogger() {
	level := logger.INFO
	switch logLevel {
	case "debug":
		level = logger.DEBUG
	case "warn":
		level = logger.WARN
	case "error":
		level = logger.ERROR
	}

	var err error
	log, err = logger.NewLogger(level, logFile, true)
	if err != nil {
		fmt.Printf("初始化日志记录器失败: %v\n", err)
		os.Exit(1)
	}
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
