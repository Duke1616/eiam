package token

import (
	"context"
	"fmt"
	"time"

	"github.com/Duke1616/eiam/ioc"
	"github.com/spf13/cobra"
)

// NewCommand 返回 token 管理子命令集合
func NewCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "token",
		Short: "EIAM 凭证与微服务令牌管理",
	}

	cmd.AddCommand(newGenCommand())
	return cmd
}

func newGenCommand() *cobra.Command {
	var serviceName string

	genCmd := &cobra.Command{
		Use:   "gen",
		Short: "为指定微服务生成专属资产自发现 Token (Service Discovery Token)",
		Long: `生成前缀为 eiam_sct_ 的强随机专属令牌，自动绑定至系统租户名下。
该 Token 仅允许对应微服务上报并对账其自身的物理接口和权限资产，有效防止跨服务误篡改。
微服务标识必须在 EIAM 服务目录中已登记，否则拒绝生成。`,
		RunE: func(cmd *cobra.Command, args []string) error {
			// NOTE: 通过 Wire 原生编排的专属 Injector 获取轻量服务实例，无胶水组装代码
			tokenSvc, err := ioc.InitTokenService()
			if err != nil {
				return fmt.Errorf("初始化令牌服务失败: %w", err)
			}

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			token, err := tokenSvc.GenerateToken(ctx, serviceName)
			if err != nil {
				return fmt.Errorf("生成令牌失败: %w", err)
			}

			fmt.Println("================================================================================")
			fmt.Printf("✔ 微服务 [%s] 资产自发现 Token 生成成功！\n", serviceName)
			fmt.Println("================================================================================")
			fmt.Printf("Token: %s\n\n", token)
			fmt.Println("使用说明：")
			fmt.Println("1. 确保 EIAM 服务端 config.yaml 中已配置开启认证:")
			fmt.Println("   discovery:")
			fmt.Println("     auth_enabled: true")
			fmt.Println()
			fmt.Printf("2. 在微服务 [%s] 的 config.yaml 中配置此令牌:\n", serviceName)
			fmt.Println("   policy:")
			fmt.Println("     discovery_url: \"http://<eiam-host>:<port>\"")
			fmt.Printf("     discovery_token: \"%s\"\n", token)
			fmt.Println("================================================================================")

			return nil
		},
	}

	genCmd.Flags().StringVarP(&serviceName, "service", "s", "", "微服务标识码 (例如: ecmdb, etask)")
	_ = genCmd.MarkFlagRequired("service")

	return genCmd
}
