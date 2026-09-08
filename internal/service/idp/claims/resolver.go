package claims

import (
	"context"

	"github.com/Duke1616/eiam/internal/domain"
	"github.com/Duke1616/eiam/internal/repository"
	"github.com/Duke1616/eiam/internal/service/permission"
	"github.com/Duke1616/eiam/pkg/ctxutil"
)

// IdentityRef 身份凭证摘要
// 来自经过校验的凭证（Token / AuthCode / ST / Session），是调用 Resolve 的最小必要输入集
// 字段均来自已验证凭证，调用方无需额外查询即可填充
type IdentityRef struct {
	TenantID int64  // 凭证绑定的目标租户（必填）
	UserID   int64  // 用户 ID（必填）
	Username string // 用户名（可选，有则省去后续 DB 兜底查询）
}

// IClaimsResolver 统一身份声明解析器
// 职责：在多租户隔离下，以已验证身份凭证摘要为输入，装配完整用户资料与租户生效角色
// 默认全量解析（含角色），可通过 opts 控制行为
type IClaimsResolver interface {
	Resolve(ctx context.Context, ref IdentityRef, opts ...ResolveOption) (Claims, error)
}

// -----------------------------------------------------------------------
// Functional Options —— 仅用于行为控制，不承载输入数据
// -----------------------------------------------------------------------

// resolveOptions 行为配置项（零值即安全默认：加载角色、无预置数据）
type resolveOptions struct {
	skipRoles bool         // 跳过多租户角色查询（默认 false）
	user      *domain.User // 预置完整用户实体，跳过 userRepo.FindById
}

// ResolveOption 行为选项函数
type ResolveOption func(*resolveOptions)

// WithoutRoles 跳过角色查询（适合仅需基础身份信息的场景）
func WithoutRoles() ResolveOption {
	return func(o *resolveOptions) { o.skipRoles = true }
}

// WithUser 预置已持有的用户实体（跳过 userRepo.FindById，适合已验票且持有完整实体的场景）
func WithUser(u domain.User) ResolveOption {
	return func(o *resolveOptions) { o.user = &u }
}

// -----------------------------------------------------------------------
// 实现
// -----------------------------------------------------------------------

type claimsResolver struct {
	userRepo repository.IUserRepository
	permSvc  permission.IPermissionService
}

// NewClaimsResolver 构造统一身份声明解析器
func NewClaimsResolver(userRepo repository.IUserRepository, permSvc permission.IPermissionService) IClaimsResolver {
	return &claimsResolver{userRepo: userRepo, permSvc: permSvc}
}

// Resolve 以身份凭证摘要为输入，解析当前租户下用户的完整标准化身份声明
// tenantID 由 ref 携带，Resolver 内部统一注入 ctx，调用方无需手动操作租户上下文
func (r *claimsResolver) Resolve(ctx context.Context, ref IdentityRef, opts ...ResolveOption) (Claims, error) {
	o := applyOptions(opts)

	// 租户上下文注入由 Resolver 统一封装，对调用方透明
	ctx = ctxutil.WithTenantID(ctx, ref.TenantID)

	user, err := r.resolveUser(ctx, ref, o)
	if err != nil {
		return Claims{}, err
	}

	roles, err := r.resolveRoles(ctx, user.Username, o)
	if err != nil {
		return Claims{}, err
	}

	return FromUser(user, ref.TenantID, roles), nil
}

// applyOptions 应用行为选项
func applyOptions(opts []ResolveOption) resolveOptions {
	o := resolveOptions{}
	for _, opt := range opts {
		opt(&o)
	}
	return o
}

// resolveUser 获取用户资料：
//  1. 优先使用 opts 预置的完整实体（零 IO）
//  2. 其次按 ref.UserID 查询 Repo
//  3. 兜底：仅用 ref.Username 构造最小实体（无 ID 场景）
func (r *claimsResolver) resolveUser(ctx context.Context, ref IdentityRef, o resolveOptions) (domain.User, error) {
	if o.user != nil {
		return *o.user, nil
	}

	if ref.UserID > 0 {
		return r.userRepo.FindById(ctx, ref.UserID)
	}

	return domain.User{Username: ref.Username}, nil
}

// resolveRoles 获取当前租户下用户生效角色（WithoutRoles 或 username 为空时跳过）
func (r *claimsResolver) resolveRoles(ctx context.Context, username string, o resolveOptions) ([]string, error) {
	if o.skipRoles || username == "" {
		return nil, nil
	}

	return r.permSvc.GetRolesForUser(ctx, username)
}
