package user

import (
	"context"

	"github.com/Duke1616/eiam/internal/domain"
)

// IdentityProvider 身份提供者策略接口。
// 认证器直接负责将外部认证系统的结果，原汁原味地映射为系统内核识别的 domain.User 对象。
type IdentityProvider interface {
	// Name 返回身份源唯一标识 (ldap, feishu 等)
	Name() string
	// Authenticate 执行外部身份核验，返回构造完毕的领域用户模型
	Authenticate(ctx context.Context, username, password string) (domain.User, error)
}
