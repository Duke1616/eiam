package permission

type Permission struct {
	ID      int64  `json:"id"`
	Service string `json:"service"`
	Group   string `json:"group"`
	Code    string `json:"code"`
	Name    string `json:"name"`
}

// Manifest 权限清单，用于前端归一化管理逻辑能力项
type Manifest struct {
	Actions  []Permission             `json:"actions"`
	Services []ServicePermissionEntry `json:"services"`
}

type ServicePermissionEntry struct {
	Code    string  `json:"code"`
	Name    string  `json:"name"`
	Entries []Entry `json:"entries"`
}

type Entry struct {
	Name    string   `json:"name"`
	Actions []string `json:"actions"`
}

type BindResourcesRequest struct {
	PermID   int64    `json:"perm_id" binding:"required"`
	PermCode string   `json:"perm_code" binding:"required"`
	ResURNs  []string `json:"res_urns" binding:"required"`
}

type AssignRoleRequest struct {
	UserID   int64  `json:"user_id" binding:"required"`
	RoleCode string `json:"role_code" binding:"required"`
}

type AttachPolicyReq struct {
	RoleCode string `json:"role_code"`
	PolyCode string `json:"poly_code"`
}

type CheckPolicyReq struct {
	Service  string `json:"service"`
	Path     string `json:"path"`
	Method   string `json:"method"`
	Resource string `json:"resource"`
}

type AuthorizeResult struct {
	Allowed bool   `json:"allowed"`
	Reason  string `json:"reason"`
}

type Menu struct {
	ID        int64  `json:"id"`
	ParentID  int64  `json:"parent_id"`
	Name      string `json:"name"`
	Path      string `json:"path"`
	Component string `json:"component"`
	Redirect  string `json:"redirect"`
	Meta      Meta   `json:"meta"`
	Children  []Menu `json:"children,omitempty"`
}

type Meta struct {
	Title       string   `json:"title"`
	Icon        string   `json:"icon"`
	IsHidden    bool     `json:"is_hidden"`
	IsKeepAlive bool     `json:"is_keepalive"`
	IsAffix     bool     `json:"is_affix"`
	Platforms   []string `json:"platforms"`
}
