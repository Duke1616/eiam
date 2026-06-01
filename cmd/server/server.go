package server

import (
	"context"
	"time"

	"github.com/Duke1616/eiam/ioc"
	"github.com/gotomicro/ego"
	"github.com/gotomicro/ego/core/elog"
	"github.com/gotomicro/ego/server"
	"github.com/spf13/cobra"
)

// NewCommand 返回 server 子命令。
func NewCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "server",
		Short: "启动服务节点",
		Run: func(cmd *cobra.Command, args []string) {
			startServer()
		},
	}
}

// startServer 启动业务节点的完整生命周期
func startServer() {
	// 调用 wire 生成的注入逻辑，注入全链路 Service/Repo/Handler
	app, err := ioc.InitApp()
	if err != nil {
		elog.Panic("dependency_injection_failed", elog.FieldErr(err))
	}

	// 执行物理资产初始化与 API 自动发现
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// 1. 自动化发现并上报 EIAM 本身的资产 (逻辑权限与物理 API)
	// 这里底层复用了 SDK 的分布式注册逻辑，会自动在多实例间选主报备
	_ = app.Init.SyncDiscoveryAPIs(ctx, app.Providers, app.Web.Engine)

	// 2. 启动后台异步任务 (Tasks) —— 如资产发现调度器、内置资产同步器等
	for _, task := range app.Tasks {
		task.Start(context.Background())
	}

	// 创建 ego 应用实例
	egoApp := ego.New(ego.WithDisableBanner(true))

	// 启动服务
	if err = egoApp.Serve(
		func() server.Server {
			return app.Web
		}(),
		func() server.Server {
			return app.Server
		}(),
	).Cron().
		Run(); err != nil {
		elog.Panic("startup", elog.FieldErr(err))
	}
}
