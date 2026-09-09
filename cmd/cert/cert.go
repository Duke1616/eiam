package cert

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/Duke1616/eiam/pkg/certx"
	"github.com/spf13/cobra"
)

// NewCommand 返回 cert 证书管理子命令集合
func NewCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "cert",
		Short: "EIAM 证书管理与离线生成工具",
	}

	cmd.AddCommand(newGenCommand())
	return cmd
}

func newGenCommand() *cobra.Command {
	var (
		commonName   string
		organization string
		validityDays int
		bits         int
		outDir       string
	)

	genCmd := &cobra.Command{
		Use:   "gen",
		Short: "离线生成 X.509 自签名证书与配套 RSA 私钥",
		Long: `生成标准的自签名 X.509 证书 (.crt) 与 RSA 私钥 (.key)，可用于离线部署、
Kubernetes Secret 挂载或基础设施 mTLS/SAML 集成。`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if validityDays <= 0 {
				validityDays = 1095 // 默认 3 年 (1095 天)
			}
			if bits <= 0 {
				bits = 2048
			}

			cfg := certx.CertConfig{
				CommonName:   commonName,
				Organization: organization,
				Validity:     time.Duration(validityDays) * 24 * time.Hour,
				KeyBits:      bits,
			}

			bundle, err := certx.GenerateSelfSigned(cfg)
			if err != nil {
				return fmt.Errorf("生成证书失败: %w", err)
			}

			if err := os.MkdirAll(outDir, 0755); err != nil {
				return fmt.Errorf("创建输出目录失败: %w", err)
			}

			certPath := filepath.Join(outDir, "saml.crt")
			keyPath := filepath.Join(outDir, "saml.key")
			combinedPath := filepath.Join(outDir, "saml.pem")

			if err := os.WriteFile(certPath, []byte(bundle.CertPEM()), 0644); err != nil {
				return fmt.Errorf("写入证书文件失败: %w", err)
			}
			if err := os.WriteFile(keyPath, []byte(bundle.KeyPEM()), 0600); err != nil {
				return fmt.Errorf("写入私钥文件失败: %w", err)
			}
			if err := os.WriteFile(combinedPath, []byte(bundle.CombinedPEM()), 0600); err != nil {
				return fmt.Errorf("写入合并 PEM 文件失败: %w", err)
			}

			fmt.Println("================================================================================")
			fmt.Printf("✔ 自签名证书与私钥生成成功！\n")
			fmt.Println("================================================================================")
			fmt.Printf("主体名称 (CN)   : %s\n", bundle.CommonName())
			fmt.Printf("所属组织 (O)    : %s\n", organization)
			fmt.Printf("有效天数 (Days) : %d 天 (至 %s)\n", validityDays, bundle.X509.NotAfter.Format("2006-01-02 15:04:05"))
			fmt.Printf("SHA-256 指纹    : %s\n\n", bundle.Fingerprint())
			fmt.Printf("证书文件 (.crt) : %s\n", certPath)
			fmt.Printf("私钥文件 (.key) : %s\n", keyPath)
			fmt.Printf("合并凭据 (.pem) : %s\n", combinedPath)
			fmt.Println("================================================================================")
			return nil
		},
	}

	genCmd.Flags().StringVar(&commonName, "cn", "EIAM SAML Identity Provider", "证书主体名称 (Common Name)")
	genCmd.Flags().StringVar(&organization, "org", "EIAM Enterprise", "所属组织名称 (Organization)")
	genCmd.Flags().IntVar(&validityDays, "days", 1095, "证书有效天数 (默认 1095 天)")
	genCmd.Flags().IntVar(&bits, "bits", 2048, "RSA 密钥位数 (默认 2048 位)")
	genCmd.Flags().StringVar(&outDir, "out", "./certs", "证书输出目录 (默认 ./certs)")

	return genCmd
}
