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
		func(ctx context.Context, keyword string, offset, limit int64) ([]domain.Role, error) {
			return roleSvc.Search(ctx, keyword, offset, limit)
		},
		func(ctx context.Context, keyword string) (int64, error) {
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
		func(ctx context.Context, keyword string, offset, limit int64) ([]domain.User, error) {
			return userSvc.Search(ctx, keyword, offset, limit)
		},
		func(ctx context.Context, keyword string) (int64, error) {
			return userSvc.CountSearch(ctx, keyword)
		},
		func(src domain.User) searcher.Subject {
			return searcher.Subject{Type: domain.SubjectTypeUser, ID: src.Username, Name: src.Profile.Nickname}
		},
	)
}
