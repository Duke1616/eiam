package main

import (
	"fmt"
	"os"

	"github.com/Duke1616/eiam/pkg/gen/swagger"
	"github.com/spf13/cobra"
)

var (
	scanDir  string
	jsonOut  string
	htmlOut  string
	apiTitle string
	version  string
)

func main() {
	rootCmd := &cobra.Command{
		Use:   "swaggergen",
		Short: "EIAM 平台零注释 OpenAPI / Swagger 静态文档与交互式预览生成器",
		Long: `swaggergen 是独立解耦的 API 文档生成工具。
它通过静态分析 Handler 路由、请求参数与分组定义，
自动导出标准的 OpenAPI 3.0 (swagger.json) 以及开箱即用的交互式预览网页 (index.html)。`,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Printf("[swaggergen] 正在扫描 HTTP 路由与端点定义 (%s)...\n", scanDir)
			parser := swagger.NewParser()
			endpoints, structs, err := parser.ParseDir(scanDir)
			if err != nil {
				return fmt.Errorf("扫描路由失败: %w", err)
			}

			fmt.Printf("[swaggergen] 解析完成: 提取出 %d 个路由端点，%d 个请求模型\n", len(endpoints), len(structs))

			gen := swagger.NewGenerator(apiTitle, version)
			if err = gen.Generate(endpoints, structs, jsonOut, htmlOut); err != nil {
				return fmt.Errorf("生成文档失败: %w", err)
			}

			fmt.Printf("[swaggergen] 生成 OpenAPI 3.0 规范文件: %s\n", jsonOut)
			if htmlOut != "" {
				fmt.Printf("[swaggergen] 生成交互式预览页面: %s\n", htmlOut)
				fmt.Printf("[swaggergen] 提示: 可直接在浏览器中打开 %s 预览完整接口文档\n", htmlOut)
			}
			fmt.Println("[swaggergen] 执行完毕")
			return nil
		},
	}

	flags := rootCmd.Flags()
	flags.StringVarP(&scanDir, "scan", "s", "./internal/web", "AST 扫描的源码根目录")
	flags.StringVarP(&jsonOut, "out", "o", "./api/docs/swagger.json", "OpenAPI JSON 文档输出路径")
	flags.StringVar(&htmlOut, "html", "./api/docs/index.html", "交互式预览 HTML 页面输出路径 (置空则不生成)")
	flags.StringVarP(&apiTitle, "title", "t", "EIAM API Documentation", "接口文档主标题")
	flags.StringVarP(&version, "version", "v", "1.0.0", "文档版本号")

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
