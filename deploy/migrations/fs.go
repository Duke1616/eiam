// Package migrations 提供嵌入式 SQL 迁移文件，供 goose 在启动时自动执行。
package migrations

import "embed"

// FS 包含 deploy/migrations 目录下所有 .sql 迁移文件。
//
//go:embed *.sql
var FS embed.FS
