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
	}
}
