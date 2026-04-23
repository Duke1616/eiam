package domain

// Tenant 租户空间主体
type Tenant struct {
	ID              int64
	Name            string
	Code            string // 租户编码：唯一标识，如 "acme"
	Domain          string // 绑定域名
	Status          int    // 1-活跃, 2-禁用
	Ctime           int64
	Utime           int64
}

// Membership 租户成员关联：这只是你和租户之间的"入驻契约"。
// 一切关于"你能干啥"的授权，全部移交给 Casbin 或 RoleService 处理。
type Membership struct {
	ID       int64
	TenantID int64
	UserID   int64
	Ctime    int64
}
