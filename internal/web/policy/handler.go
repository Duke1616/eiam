package policy

import (
	"encoding/json"
	"errors"
	"strings"

	"github.com/Duke1616/eiam/internal/domain"
	permsvc "github.com/Duke1616/eiam/internal/service/permission"
	policysvc "github.com/Duke1616/eiam/internal/service/policy"
	usersvc "github.com/Duke1616/eiam/internal/service/user"
	"github.com/Duke1616/eiam/pkg/web/capability"
	"github.com/ecodeclub/ekit/slice"
	"github.com/ecodeclub/ginx"
	"github.com/gin-gonic/gin"
)

type Handler struct {
	capability.IRegistry
	svc     policysvc.IPolicyService
	userSvc usersvc.IUserService
	permSvc permsvc.IPermissionService
}

func NewHandler(svc policysvc.IPolicyService, userSvc usersvc.IUserService, permSvc permsvc.IPermissionService) *Handler {
	return &Handler{
		IRegistry: capability.NewRegistry("iam", "policy", "策略管理"),
		svc:       svc,
		userSvc:   userSvc,
		permSvc:   permSvc,
	}
}

func (h *Handler) PublicRoutes(server *gin.Engine) {
	// 策略管理暂无公开接口
}

func (h *Handler) PrivateRoutes(server *gin.Engine) {
	g := server.Group("/api/policy")

	g.POST("/create", h.Capability("创建策略", "add").
		Handle(ginx.B[CreatePolicyReq](h.CreatePolicy)),
	)
	g.POST("/update", h.Capability("修改策略", "edit").
		Handle(ginx.B[UpdatePolicyReq](h.UpdatePolicy)),
	)
	g.POST("/list", h.Capability("策略列表", "view").
		Handle(ginx.B[ListPolicyReq](h.ListPolicies)),
	)
	g.GET("/detail/:code", h.Capability("策略详情", "view").
		Handle(ginx.W(h.GetPolicyDetail)),
	)
	g.POST("/attach", h.Capability("绑定策略", "attach").
		Handle(ginx.B[AttachPolicyReq](h.AttachPolicy)),
	)
	g.POST("/detach", h.Capability("解绑策略", "detach").
		Handle(ginx.B[AttachPolicyReq](h.DetachPolicy)),
	)
	g.POST("/batch-attach", h.Capability("批量绑定策略", "batch-attach").
		Handle(ginx.B[BatchAttachPolicyReq](h.BatchAttachPolicy)),
	)
	// 查询特定用户的关联策略 (管理侧使用)
	g.POST("/list/attached/user", h.Capability("查询用户策略", "view_user_policies").
		Handle(ginx.B[ListUserPoliciesReq](h.GetPoliciesByUserId)),
	)
}

func (h *Handler) GetPoliciesByUserId(ctx *ginx.Context, req ListUserPoliciesReq) (ginx.Result, error) {
	id := req.UserID
	if id == 0 {
		return ErrInvalidUserId, nil
	}

	// 设置默认分页
	if req.Limit <= 0 {
		req.Limit = 10
	}

	// 1. 获取用户信息，拿到 username
	u, err := h.userSvc.GetById(ctx.Request.Context(), id)
	if err != nil {
		return ErrGetUserFailed, err
	}

	// 2. 分页获取该用户关联的策略
	ps, total, err := h.svc.ListAttachedPolicies(ctx.Request.Context(), domain.SubjectTypeUser, u.Username, req.Offset, req.Limit, req.Keyword, domain.PolicyType(req.Type))
	if err != nil {
		return ErrGetAttachedFailed, err
	}

	return ginx.Result{
		Data: ListPolicyRes{
			Total: total,
			Policies: slice.Map(ps, func(idx int, src domain.Policy) Policy {
				return h.toVO(src)
			}),
		},
	}, nil
}

func (h *Handler) CreatePolicy(ctx *ginx.Context, req CreatePolicyReq) (ginx.Result, error) {
	_, err := h.svc.CreatePolicy(ctx.Request.Context(), domain.Policy{
		Name: req.Name,
		Code: req.Code,
		Desc: req.Desc,
		Type: domain.PolicyType(req.Type),
		Statement: slice.Map(req.Statement, func(idx int, s Statement) domain.Statement {
			return h.toStatementDomain(s)
		}),
	})
	if err != nil {
		if errors.Is(err, domain.ErrDuplicatePolicyCode) {
			return ErrDuplicatePolicyCode, err
		}
		return ErrCreatePolicyFailed, err
	}
	return ginx.Result{Msg: "创建成功"}, nil
}

func (h *Handler) UpdatePolicy(ctx *ginx.Context, req UpdatePolicyReq) (ginx.Result, error) {
	err := h.svc.UpdatePolicy(ctx.Request.Context(), domain.Policy{
		Name: req.Name,
		Code: req.Code,
		Desc: req.Desc,
		Statement: slice.Map(req.Statement, func(idx int, s Statement) domain.Statement {
			return h.toStatementDomain(s)
		}),
	})
	if err != nil {
		return ErrUpdatePolicyFailed, err
	}
	return ginx.Result{Msg: "更新成功"}, nil
}

func (h *Handler) ListPolicies(ctx *ginx.Context, req ListPolicyReq) (ginx.Result, error) {
	ps, total, err := h.svc.SearchPolicies(ctx.Request.Context(), req.Offset, req.Limit, req.Keyword, domain.PolicyType(req.Type))
	if err != nil {
		return ErrListPolicyFailed, err
	}

	return ginx.Result{
		Data: ListPolicyRes{
			Total: total,
			Policies: slice.Map(ps, func(idx int, src domain.Policy) Policy {
				return h.toVO(src)
			}),
		},
	}, nil
}

func (h *Handler) AttachPolicy(ctx *ginx.Context, req AttachPolicyReq) (ginx.Result, error) {
	err := h.svc.AttachPolicyToRole(ctx.Request.Context(), req.RoleCode, req.PolicyCode)
	if err != nil {
		return ErrAttachPolicyFailed, err
	}
	return ginx.Result{Msg: "绑定成功"}, nil
}

func (h *Handler) DetachPolicy(ctx *ginx.Context, req AttachPolicyReq) (ginx.Result, error) {
	err := h.svc.DetachFromRole(ctx.Request.Context(), req.RoleCode, req.PolicyCode)
	if err != nil {
		return ErrDetachPolicyFailed, err
	}
	return ginx.Result{Msg: "解绑成功"}, nil
}

func (h *Handler) BatchAttachPolicy(ctx *ginx.Context, req BatchAttachPolicyReq) (ginx.Result, error) {
	subjects := slice.Map(req.Subjects, func(idx int, src SubjectItem) domain.Subject {
		return domain.Subject{
			Type: src.Type,
			ID:   src.Code,
		}
	})

	res, err := h.svc.BatchAttachPolicies(ctx.Request.Context(), subjects, req.PolicyCodes)
	if err != nil {
		return ErrBatchAttachPolicyFailed, err
	}

	return ginx.Result{
		Msg: "批量绑定成功",
		Data: BatchAttachPolicyRes{
			Total:    res.Total,
			Inserted: res.Inserted,
			Ignored:  res.Ignored,
		},
	}, nil
}

func (h *Handler) GetPolicyDetail(ctx *ginx.Context) (ginx.Result, error) {
	code, err := ctx.Param("code").AsString()
	if err != nil {
		return ErrInvalidPolicyCode, err
	}

	// 1. 获取策略基本信息
	p, err := h.svc.GetPolicy(ctx.Request.Context(), code)
	if err != nil {
		return ErrGetPolicyFailed, err
	}

	// 2. 获取权限服务维度的摘要分析
	summary, err := h.permSvc.GetPolicySummary(ctx.Request.Context(), p)
	if err != nil {
		return ErrGetSummaryFailed, err
	}

	return ginx.Result{
		Data: RetriePolicySummaryRes{
			Policy: h.toVO(p),
			Services: slice.Map(summary.Services, func(idx int, src domain.PolicyServiceSummary) ServiceSummary {
				return ServiceSummary{
					ServiceCode:   src.ServiceCode,
					ServiceName:   src.ServiceName,
					Level:         string(src.Level),
					GrantedCount:  src.GrantedCount,
					TotalCount:    src.TotalCount,
					ResourceScope: src.ResourceScope,
					Condition: func() string {
						if len(src.Conditions) == 0 {
							return "-"
						}
						b, _ := json.Marshal(src.Conditions)
						return string(b)
					}(),
					Actions: slice.Map(src.Actions, func(idx int, pct domain.GrantedAction) ActionDetail {
						// 格式化资源
						resStr := strings.Join(pct.Resource, ", ")

						// 格式化条件
						condStr := "-"
						if len(pct.Condition) > 0 {
							b, _ := json.Marshal(pct.Condition)
							condStr = string(b)
						}

						return ActionDetail{
							Code:      pct.Code,
							Name:      pct.Name,
							Group:     pct.Group,
							Resource:  resStr,
							Condition: condStr,
						}
					}),
				}
			}),
		},
	}, nil
}

func (h *Handler) toVO(p domain.Policy) Policy {
	return Policy{
		ID:              p.ID,
		Name:            p.Name,
		Code:            p.Code,
		Desc:            p.Desc,
		Type:            uint8(p.Type),
		Ctime:           p.Ctime,
		AssignmentCount: p.AssignmentCount,
		Statement: slice.Map(p.Statement, func(idx int, s domain.Statement) Statement {
			return Statement{
				Effect:   string(s.Effect),
				Action:   s.Action,
				Resource: s.Resource,
				Condition: slice.Map(s.Condition, func(idx int, c domain.Condition) Condition {
					return Condition{
						Operator: c.Operator,
						Key:      c.Key,
						Value:    c.Value,
					}
				}),
			}
		}),
	}
}

func (h *Handler) toStatementDomain(s Statement) domain.Statement {
	return domain.Statement{
		Effect:   domain.Effect(s.Effect),
		Action:   s.Action,
		Resource: s.Resource,
		Condition: slice.Map(s.Condition, func(idx int, c Condition) domain.Condition {
			return domain.Condition{
				Operator: c.Operator,
				Key:      c.Key,
				Value:    c.Value,
			}
		}),
	}
}
