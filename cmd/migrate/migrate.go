package migrate

import (
	"context"
	"log"
	"os"

	"github.com/Duke1616/eiam/cmd/migrate/internal/config"
	"github.com/Duke1616/eiam/cmd/migrate/internal/migration"
	"github.com/Duke1616/eiam/cmd/migrate/internal/migrations"
	"github.com/spf13/cobra"
)

// NewCommand 返回 migrate 子命令。
func NewCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "migrate",
		Short: "执行数据迁移",
		Run: func(cmd *cobra.Command, args []string) {
			runMigrate()
		},
	}

	return cmd
}

func init() {
	log.SetOutput(os.Stdout)
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)
}

func runMigrate() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("使用迁移配置: %s", cfg.ConfigFile)

	ctx, cancel := context.WithTimeout(context.Background(), cfg.Timeout)
	defer cancel()

	runner := migration.NewRunner(cfg, migrations.All(cfg.EncryptionKey, cfg.EncryptionVersion),
		migration.WithPreHooks(migrations.PreHooks()...),
		migration.WithPostHooks(migrations.PostHooks()...),
	)
	if err = runner.Run(ctx); err != nil {
		log.Fatal(err)
	}
	log.Println("迁移完成")
}
