package identity_source

import (
	"context"

	"github.com/Duke1616/eiam/internal/domain"
)

// IService 身份源管理服务接口
type IService interface {
	// Save 保存或更新身份源配置
	// 如果是 LDAP 类型，会对 Config 中的敏感信息进行加密存储
	Save(ctx context.Context, source domain.IdentitySource) (int64, error)

	// List 获取当前租户下的所有身份源列表
	List(ctx context.Context) ([]domain.IdentitySource, error)

	// GetByID 根据 ID 获取身份源详情
	GetByID(ctx context.Context, id int64) (domain.IdentitySource, error)

	// Delete 删除指定的身份源
	Delete(ctx context.Context, id int64) error

	// TestConnection 测试身份源连通性
	// 在保存配置前调用，用于校验 URL、账号密码及过滤条件的有效性
	TestConnection(ctx context.Context, source domain.IdentitySource) error
}
