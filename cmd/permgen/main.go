package main

import (
	"fmt"
	"os"

	"github.com/Duke1616/eiam/pkg/gen/capability"
	"github.com/spf13/cobra"
)

var (
	// Version 与 BuildTime 支持通过 ldflags 在编译期注入
	Version   = "v1.0.0"
	BuildTime = "unknown"
)

func main() {
	var cfg capability.Config

	rootCmd := &cobra.Command{
		Use:   "permgen",
		Short: "EIAM 权限 AST 静态扫描与强类型契约代码生成器",
		Long: `PermGen 是专为 EIAM 及生态微服务 (如 etask、eflow) 打造的权限静态分析与代码生成脚手架。
无需启动服务，在编译期静态分析 Handler 路由并导出全套强类型契约代码与权限大盘蓝图文档。`,
		Version: fmt.Sprintf("%s (build %s)", Version, BuildTime),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			engine := capability.NewEngine(cfg)
			return engine.Run(cmd.Context())
		},
	}

	flags := rootCmd.Flags()
	flags.StringVarP(&cfg.ScanDir, "scan", "s", "./internal/web", "AST 扫描的源码根目录")
	flags.StringVarP(&cfg.GoOut, "go-out", "g", "./pkg/contract/permission/zz_generated_perms.go", "Go 强类型权限契约代码输出路径")
	flags.StringVarP(&cfg.ModelOut, "model-out", "m", "./pkg/contract/model/zz_generated_models.go", "业务领域模型元数据代码输出路径")
	flags.StringVarP(&cfg.DocOut, "doc-out", "d", "./docs/permissions.md", "权限大盘蓝图字典文档输出路径")
	flags.BoolVar(&cfg.StrictMode, "strict", false, "严格模式：检测到依赖死锁或未定义等错误时阻断退出")

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
