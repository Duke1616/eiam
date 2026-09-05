package invitation

type Page struct {
	Offset   int `json:"offset"`
	Limit    int `json:"limit"`
	Page     int `json:"page"`
	PageSize int `json:"page_size"`
}

type CreateInvitationReq struct {
	MaxUses         int      `json:"max_uses"`
	ExpiryDays      int      `json:"expiry_days"` // 前端按天传，后端计算成毫秒
	RoleCodes       []string `json:"role_codes"`
	RequireApproval bool     `json:"require_approval"`
}

type AcceptInvitationReq struct {
	Code string `json:"code" binding:"required"`
}

type BatchRevokeInvitationReq struct {
	Codes []string `json:"codes" binding:"required"`
}

type HandleJoinRequestReq struct {
	ID      int64 `json:"id" binding:"required"`
	Approve bool  `json:"approve"`
}

type Invitation struct {
	Code            string   `json:"code"`
	TenantID        int64    `json:"tenant_id"`
	TenantName      string   `json:"tenant_name"`
	InviterID       int64    `json:"inviter_id"`
	RoleCodes       []string `json:"role_codes"`
	MaxUses         int      `json:"max_uses"`
	UsedCount       int      `json:"used_count"`
	ExpireAt        int64    `json:"expire_at"`
	RequireApproval bool     `json:"require_approval"`
	IsMember        bool     `json:"is_member"` // 当前用户是否已经是成员
}

type JoinRequest struct {
	ID             int64    `json:"id"`
	UserID         int64    `json:"user_id"`
	Username       string   `json:"username"`
	Nickname       string   `json:"nickname"`
	InvitationCode string   `json:"invitation_code"`
	RoleCodes      []string `json:"role_codes"`
	Ctime          int64    `json:"ctime"`
}

type RetrieveInvitations struct {
	Total       int64        `json:"total"`
	Invitations []Invitation `json:"invitations"`
}

type RetrieveJoinRequests struct {
	Total    int64         `json:"total"`
	Requests []JoinRequest `json:"requests"`
}
