package domain

import "time"

// 租户是业务隔离的物理边界，Member 是联通 User 和 Tenant 的桥梁。

type TenantType int8

const (
	TenantTypePersonal TenantType = iota + 1 // 个人空间
	TenantTypeOrg                            // 共享空间
)

type Tenant struct {
	ID      int64
	Name    string
	Code    string
	Type    TenantType
	OwnerID int64 // 租户的初始管理员
	Status  int8  // 1: 正常, 2: 禁用
	Ctime   time.Time
	Utime   time.Time
}

// Member 租户成员关联
type Member struct {
	ID       int64
	TenantID int64
	UserID   int64
	RoleIDs  []int64 // 该成员拥有的角色 ID 列表
	Status   int8    // 1: 正常, 2: 邀请中 (如该成员还未确认加入)
	JoinedAt time.Time
}
