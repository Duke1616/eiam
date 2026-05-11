package domain

import "time"

type InvitationStatus uint8

const (
	InvitationStatusPending InvitationStatus = 1
	InvitationStatusUsed    InvitationStatus = 2 // 针对一次性链接
	InvitationStatusExpired InvitationStatus = 3
)

type Invitation struct {
	ID              int64
	TenantID        int64
	InviterID       int64
	Code            string
	RoleCodes       []string
	MaxUses         int
	UsedCount       int
	ExpireAt        int64
	Status          InvitationStatus
	RequireApproval bool // 是否需要审批
	Ctime           int64

	// 冗余字段，用于展示
	TenantName string
}

type JoinRequestStatus uint8

const (
	JoinRequestStatusPending  JoinRequestStatus = 1
	JoinRequestStatusApproved JoinRequestStatus = 2
	JoinRequestStatusRejected JoinRequestStatus = 3
)

type JoinRequest struct {
	ID             int64
	TenantID       int64
	UserID         int64
	InvitationCode string
	RoleCodes      []string
	Status         JoinRequestStatus
	Ctime          int64

	// 冗余显示
	Username string
	Nickname string
}

func (i Invitation) IsExpired() bool {
	return i.ExpireAt > 0 && i.ExpireAt < time.Now().UnixMilli()
}

func (i Invitation) CanUse() bool {
	if i.Status != InvitationStatusPending {
		return false
	}
	if i.MaxUses > 0 && i.UsedCount >= i.MaxUses {
		return false
	}
	return true
}
