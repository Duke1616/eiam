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
	Offset int64 `json:"offset"`
	Limit  int64 `json:"limit"`
}

type ListPolicyRes struct {
	Total    int64    `json:"total"`
	Policies []Policy `json:"policies"`
}

type AttachPolicyReq struct {
	RoleCode string `json:"role_code"`
	PolyCode string `json:"poly_code"`
}
