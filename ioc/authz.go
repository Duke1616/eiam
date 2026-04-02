package ioc

import (
	"context"
	"fmt"

	"github.com/Duke1616/eiam/internal/authz"
)

// InitOPA 初始化 OPA 鉴权引擎
func InitOPA() authz.IAuthorizer {
	// 创建 OPA 鉴权器。由于是初始化阶段，使用 Background Context
	authorizer, err := authz.NewOPAAuthorizer(context.Background())
	if err != nil {
		panic(fmt.Sprintf("无法初始化 OPA 鉴权引擎: %v", err))
	}
	return authorizer
}
