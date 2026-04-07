package permission

import (
	permissionsvc "github.com/Duke1616/eiam/internal/service/permission"
	"github.com/Duke1616/eiam/pkg/web/capability"
	"github.com/ecodeclub/ginx"
	"github.com/ecodeclub/ginx/session"
	"github.com/gin-gonic/gin"
)

const CodePrefix = "iam"

type Handler struct {
	svc permissionsvc.IPermissionService
}

func NewPermissionHandler(svc permissionsvc.IPermissionService) *Handler {
	return &Handler{svc: svc}
}

func (h *Handler) ProvidePermissions() []capability.Permission {
	return []capability.Permission{
		{
			Code:  "iam:permission:create",
			Name:  "录入逻辑权限",
			Group: "系统管理",
			Desc:  "允许向权限池中录入新的逻辑能力项",
		},
		{
			Code:  "system:governance",
			Name:  "全局系统治理",
			Group: "系统管理",
			Desc:  "具备租户、菜单、角色及全局用户权限的最高管理权限",
		},
		// CMDB 自发现存量权限 (待后续 CMDB 模块化重构时迁移)
		{
			Code:  "cmdb:dashboard:view",
			Name:  "资产大盘查看",
			Group: "资产中心",
			Desc:  "允许访问 CMDB 全局搜索和资产概览仪表盘",
		},
		{
			Code:  "cmdb:model:manager",
			Name:  "模型管理",
			Group: "资产中心",
			Desc:  "允许进行模型定义、关联关系拓扑及模型变更管理",
		},
		{
			Code:  "cmdb:resource:manager",
			Name:  "物理资产管理",
			Group: "资产中心",
			Desc:  "允许在资产仓库中查看、录入及维护物理设备资产",
		},
		{
			Code:  "cmdb:process:manager",
			Name:  "流程中心治理",
			Group: "工单中心",
			Desc:  "允许进行流程引擎模板、工作流审批流的定义与管理",
		},
	}
}

func (h *Handler) PrivateRoutes(server *gin.Engine) {
	g := server.Group("/api/permission")

	// 核心业务：查询当前用户的权限资产（用于前端渲染菜单）
	// TODO: 后续可增加专门的逻辑权限点 iam:menu:view
	g.GET("/menus", ginx.W(h.GetAuthorizedMenus))
}

func (h *Handler) GetAuthorizedMenus(ctx *ginx.Context) (ginx.Result, error) {
	sess, err := session.Get(ctx)
	if err != nil || sess == nil {
		return ErrAuthMenuFailed, err
	}
	uid, err := sess.Get(ctx.Request.Context(), "uid").Int64()
	if err != nil {
		return ErrAuthMenuFailed, err
	}

	menus, err := h.svc.GetAuthorizedMenus(ctx.Request.Context(), uid)
	if err != nil {
		return ErrAuthMenuFailed, err
	}

	return ginx.Result{Data: menus}, nil
}
