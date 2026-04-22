package ioc

import (
	"context"

	"github.com/Duke1616/eiam/internal/domain"
	"github.com/Duke1616/eiam/internal/pkg/searcher"
	"github.com/Duke1616/eiam/internal/service/role"
	"github.com/Duke1616/eiam/internal/service/user"
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
			// NOTE: 角色搜索按需求维持全量/插件自动过滤逻辑，不显式锁定 tid
			return roleSvc.Search(ctx, keyword, offset, limit)
		},
		func(ctx context.Context, tid int64, keyword string) (int64, error) {
			return roleSvc.CountByKeyword(ctx, keyword)
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
			// NOTE: 用户搜索需严格遵循空间成员隔离逻辑，显式透传 tid
			return userSvc.Search(ctx, tid, keyword, offset, limit)
		},
		func(ctx context.Context, tid int64, keyword string) (int64, error) {
			return userSvc.CountSearch(ctx, tid, keyword)
		},
		func(src domain.User) searcher.Subject {
			return searcher.Subject{Type: domain.SubjectTypeUser, ID: src.Username, Name: src.Profile.Nickname}
		},
	)
}
