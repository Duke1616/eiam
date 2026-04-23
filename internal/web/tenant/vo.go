package tenant

import "github.com/Duke1616/eiam/internal/domain"

type SwitchTenantReq struct {
	TenantID int64 `json:"tenant_id" binding:"required"`
}

type CreateTenantReq struct {
	Name string `json:"name" binding:"required,max=64"`
	Code string `json:"code" binding:"required,max=32"`
}

type UpdateTenantReq struct {
	ID     int64  `json:"id" binding:"required"`
	Name   string `json:"name" binding:"required,max=64"`
	Code   string `json:"code" binding:"required,max=32"`
	Domain string `json:"domain"`
	Status int    `json:"status"`
}

type ListTenantReq struct {
	Offset int64 `json:"offset"`
	Limit  int64 `json:"limit"`
}

type ListUserTenantsReq struct {
	UserID  int64  `json:"user_id"`
	Offset  int64  `json:"offset"`
	Limit   int64  `json:"limit"`
	Keyword string `json:"keyword"`
}

type ListTenantRes struct {
	Total   int64      `json:"total"`
	Tenants []TenantVO `json:"tenants"`
}

type TenantVO struct {
	ID     int64  `json:"id"`
	Name   string `json:"name"`
	Code   string `json:"code"`
	Domain string `json:"domain"`
	Status int    `json:"status"`
	Ctime  int64  `json:"ctime"`
}

func ToTenantVOs(tenants []domain.Tenant) []TenantVO {
	res := make([]TenantVO, 0, len(tenants))
	for _, t := range tenants {
		res = append(res, ToTenantVO(t))
	}
	return res
}

func ToTenantVO(t domain.Tenant) TenantVO {
	return TenantVO{
		ID:     t.ID,
		Name:   t.Name,
		Code:   t.Code,
		Domain: t.Domain,
		Status: t.Status,
		Ctime:  t.Ctime,
	}
}

type ListMembersReq struct {
	TenantID int64  `json:"tenant_id"`
	Offset   int64  `json:"offset"`
	Limit    int64  `json:"limit"`
	Keyword  string `json:"keyword"`
}

type ListMembersRes struct {
	Total   int64      `json:"total"`
	Members []MemberVO `json:"members"`
}

type MemberVO struct {
	ID          int64  `json:"id"`
	Username    string `json:"username"`
	Nickname    string `json:"nickname"`
	Avatar      string `json:"avatar"`
	Email       string `json:"email"`
	Status      int    `json:"status"`
	JobTitle    string `json:"job_title"`
	LastLoginAt int64  `json:"last_login_at"`
	Ctime       int64  `json:"ctime"`
}

type AssignUserReq struct {
	TenantID int64 `json:"tenant_id" binding:"required"`
	UserID   int64 `json:"user_id" binding:"required"`
}
