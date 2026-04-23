package ioc

import (
	"context"

	"github.com/Duke1616/eiam/internal/domain"
	"github.com/Duke1616/eiam/internal/pkg/searcher"
	"github.com/Duke1616/eiam/internal/service/role"
	"github.com/Duke1616/eiam/internal/service/user"
	"github.com/Duke1616/eiam/pkg/ctxutil"
)

// InitSearchSubjectProviders 深度编排提供者
func InitSearchSubjectProviders(
	roleSvc role.IRoleService,
	userSvc user.IUserService,

) searcher.ISubjectRegistry {
	// 1. 构造搜索注册中心
	registry := searcher.NewSubjectRegistry()

	// 2. 注册服务
	registry.Register(NewRoleAdapter(roleSvc), NewUserAdapter(userSvc))

	return registry

}

func NewRoleAdapter(roleSvc role.IRoleService) searcher.SubjectProvider {
	return searcher.NewSubjectAdapter(
		domain.SubjectTypeRole,
		func(ctx context.Context, tid int64, keyword string, offset, limit int64) ([]domain.Role, error) {
			// 开启私有模式：在此 Context 下的查询将自动排除掉共享的系统角色 (type=1)
			return roleSvc.Search(ctxutil.WithPrivateOnly(ctx), keyword, offset, limit)
		},
		func(ctx context.Context, tid int64, keyword string) (int64, error) {
			// 开启私有模式：在此 Context 下的查询将自动排除掉共享的系统角色 (type=1)
			return roleSvc.CountByKeyword(ctxutil.WithPrivateOnly(ctx), keyword)
		},
		func(src domain.Role) searcher.Subject {
			return searcher.Subject{Type: domain.SubjectTypeRole, ID: src.Code, Name: src.Name, Desc: src.Desc}
		},
	)
}

func NewUserAdapter(userSvc user.IUserService) searcher.SubjectProvider {
	return searcher.NewSubjectAdapter(
		domain.SubjectTypeUser,
		func(ctx context.Context, tid int64, keyword string, offset, limit int64) ([]domain.User, error) {
			// NOTE: 用户搜索逻辑已下沉，通过 Context 注入 tid 以触发插件自动隔离
			return userSvc.Search(ctxutil.WithTenantID(ctx, tid), keyword, offset, limit)
		},
		func(ctx context.Context, tid int64, keyword string) (int64, error) {
			return userSvc.CountSearch(ctxutil.WithTenantID(ctx, tid), keyword)
		},
		func(src domain.User) searcher.Subject {
			return searcher.Subject{Type: domain.SubjectTypeUser, ID: src.Username, Name: src.Profile.Nickname}
		},
	)
}
