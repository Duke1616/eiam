package main

import (
	"fmt"
	"os"

	"github.com/Duke1616/eiam/ioc"
	"github.com/fsnotify/fsnotify"
	"github.com/gotomicro/ego"
	"github.com/gotomicro/ego/core/elog"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	cfgFile string
)

func main() {
	rootCmd := &cobra.Command{
		Use:   "eiam",
		Short: "EIAM 统一身份与访问管理平台",
	}

	// 1. 设置全局配置文件参数
	dir, _ := os.Getwd()
	defaultCfg := dir + "/config/config.yaml"
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", defaultCfg, "配置文件路径")

	// 2. 初始化配置中心
	cobra.OnInitialize(initViper)

	// 3. 注册启动服务的子命令
	serverCmd := &cobra.Command{
		Use:   "server",
		Short: "启动 EIAM 服务节点",
		Run: func(cmd *cobra.Command, args []string) {
			startServer()
		},
	}

	rootCmd.AddCommand(serverCmd)

	// 执行命令行
	if err := rootCmd.Execute(); err != nil {
		fmt.Printf("Command execute error: %v\n", err)
		os.Exit(1)
	}
}

// startServer 启动业务节点的完整生命周期
func startServer() {
	// 调用 wire 生成的注入逻辑，注入全链路 Service/Repo/Handler
	app, err := ioc.InitApp()
	if err != nil {
		elog.Panic("dependency_injection_failed", elog.FieldErr(err))
	}

	// 创建 ego 应用实例
	egoApp := ego.New(ego.WithDisableBanner(true))

	// 挂载 Web 服务
	if err = egoApp.Serve(app.Web).Run(); err != nil {
		elog.Panic("app_run_error", elog.FieldErr(err))
	}
}

// initViper 初始化 Viper 并支持动态监听
func initViper() {
	if cfgFile != "" {
		viper.SetConfigFile(cfgFile)
	}

	// 开启文件监控
	viper.WatchConfig()
	if err := viper.ReadInConfig(); err != nil {
		fmt.Printf("Warning: 配置文件读取失败: %v\n", err)
	} else {
		fmt.Printf("Using config file: %s\n", viper.ConfigFileUsed())
		setLogLevel() // 每次读取/重载都设置日志级别
	}

	// 监听配置变更，支持动态切换日志级别
	viper.OnConfigChange(func(in fsnotify.Event) {
		setLogLevel()
	})
}

// setLogLevel 根据配置文件中的 log.debug 动态调整全局日志级别
func setLogLevel() {
	if viper.GetBool("log.debug") {
		elog.DefaultLogger.SetLevel(elog.DebugLevel)
		elog.DefaultLogger.Debug("已根据配置开启 Debug 日志级别")
	} else {
		elog.DefaultLogger.SetLevel(elog.InfoLevel)
	}
}
