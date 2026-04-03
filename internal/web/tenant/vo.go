package tenant

import "github.com/Duke1616/eiam/internal/domain"

type SwitchTenantReq struct {
	TenantID int64 `json:"tenant_id" binding:"required"`
}

type CreateTenantReq struct {
	Name string `json:"name" binding:"required,max=64"`
	Code string `json:"code" binding:"required,max=32"`
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
		res = append(res, TenantVO{
			ID:     t.ID,
			Name:   t.Name,
			Code:   t.Code,
			Domain: t.Domain,
			Status: t.Status,
		})
	}
	return res
}
