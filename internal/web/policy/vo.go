package policy

type CreatePolicyReq struct {
	Name      string      `json:"name"`
	Code      string      `json:"code"`
	Desc      string      `json:"desc"`
	Type      uint8       `json:"type"`
	Statement []Statement `json:"statement"`
}

type UpdatePolicyReq struct {
	Name      string      `json:"name"`
	Code      string      `json:"code"`
	Desc      string      `json:"desc"`
	Statement []Statement `json:"statement"`
}

type Policy struct {
	ID        int64       `json:"id"`
	Name      string      `json:"name"`
	Code      string      `json:"code"`
	Desc      string      `json:"desc"`
	Type      uint8       `json:"type"`
	Statement []Statement `json:"statement"`
}

type Statement struct {
	Effect    string      `json:"effect"`
	Action    []string    `json:"action"`
	Resource  []string    `json:"resource"`
	Condition []Condition `json:"condition,omitempty"`
}

type Condition struct {
	Operator string `json:"operator"`
	Key      string `json:"key"`
	Value    any    `json:"value"`
}

type ListPolicyReq struct {
	Offset  int64  `json:"offset"`
	Limit   int64  `json:"limit"`
	Keyword string `json:"keyword"`
	Type    uint8  `json:"type"`
}

type ListPolicyRes struct {
	Total    int64    `json:"total"`
	Policies []Policy `json:"policies"`
}

type AttachPolicyReq struct {
	RoleCode string `json:"role_code"`
	PolyCode string `json:"poly_code"`
}

type SubjectItem struct {
	// Type 主体类型: user 或 role
	Type string `json:"type"`
	// Code 主体标识（用户名或角色代码）
	Code string `json:"code"`
}

// BatchAttachPolicyReq 批量绑定策略请求
// 支持将多个策略同时绑定到多个主体（用户和角色可以混合）
type BatchAttachPolicyReq struct {
	// Subjects 主体列表，可同时包含 user 和 role
	Subjects []SubjectItem `json:"subjects"`
	// PolicyCodes 策略代码列表
	PolicyCodes []string `json:"policy_codes"`
}

// BatchAttachPolicyRes 批量绑定结果
type BatchAttachPolicyRes struct {
	// Total 总绑定数量
	Total int64 `json:"total"`
}
