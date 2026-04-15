package policy

import (
	"github.com/Duke1616/eiam/internal/domain"
	policysvc "github.com/Duke1616/eiam/internal/service/policy"
	"github.com/Duke1616/eiam/pkg/web/capability"
	"github.com/ecodeclub/ekit/slice"
	"github.com/ecodeclub/ginx"
	"github.com/gin-gonic/gin"
)

type Handler struct {
	capability.IRegistry
	svc policysvc.IPolicyService
}

func NewHandler(svc policysvc.IPolicyService) *Handler {
	return &Handler{
		IRegistry: capability.NewRegistry("iam", "policy", "策略管理"),
		svc:       svc,
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

	g.POST("/attach", h.Capability("绑定策略", "attach").
		Handle(ginx.B[AttachPolicyReq](h.AttachPolicy)),
	)
	g.POST("/detach", h.Capability("解绑策略", "detach").
		Handle(ginx.B[AttachPolicyReq](h.DetachPolicy)),
	)
	g.POST("/batch-attach", h.Capability("批量绑定策略", "batch-attach").
		Handle(ginx.B[BatchAttachPolicyReq](h.BatchAttachPolicy)),
	)
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
		return ginx.Result{Msg: "创建策略失败"}, err
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
		return ginx.Result{Msg: "更新策略失败"}, err
	}
	return ginx.Result{Msg: "更新成功"}, nil
}

func (h *Handler) ListPolicies(ctx *ginx.Context, req ListPolicyReq) (ginx.Result, error) {
	ps, total, err := h.svc.SearchPolicies(ctx.Request.Context(), req.Offset, req.Limit, req.Keyword, domain.PolicyType(req.Type))
	if err != nil {
		return ginx.Result{Msg: "查询策略列表失败"}, err
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
	err := h.svc.AttachPolicyToRole(ctx.Request.Context(), req.RoleCode, req.PolyCode)
	if err != nil {
		return ginx.Result{Msg: "绑定策略失败"}, err
	}
	return ginx.Result{Msg: "绑定成功"}, nil
}

func (h *Handler) DetachPolicy(ctx *ginx.Context, req AttachPolicyReq) (ginx.Result, error) {
	err := h.svc.DetachFromRole(ctx.Request.Context(), req.RoleCode, req.PolyCode)
	if err != nil {
		return ginx.Result{Msg: "解绑策略失败"}, err
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
		return ginx.Result{Msg: "批量绑定策略失败"}, err
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

func (h *Handler) toVO(p domain.Policy) Policy {
	return Policy{
		ID:   p.ID,
		Name: p.Name,
		Code: p.Code,
		Desc: p.Desc,
		Type: uint8(p.Type),
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
