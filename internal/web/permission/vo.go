package permission

type CreatePermissionRequest struct {
	Code string `json:"code" binding:"required"`
	Desc string `json:"desc"`
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
