package domain

import "time"

// Menu 菜单资源 (纯展示层元数据)
type Menu struct {
	ID        int64     `json:"id"`
	ParentID  int64     `json:"parent_id"`
	TenantID  int64     `json:"tenant_id"` // 菜单支持租户隔离配置
	Name      string    `json:"name"`      // 菜单名：如 "用户列表"
	Path      string    `json:"path"`      // 路由路径：如 "/users"
	Component string    `json:"component"` // 前端组件
	Icon      string    `json:"icon"`      // 图标
	Sort      int32     `json:"sort"`      // 排序
	Hidden    bool      `json:"hidden"`    // 是否在菜单栏隐藏
	Ctime     time.Time `json:"ctime"`
	Utime     time.Time `json:"utime"`
}

// API 接口资源 (纯接口层元数据)
type API struct {
	ID      int64     `json:"id"`
	Service string    `json:"service"` // 所属服务标识：如 "iam", "cmdb"
	Name    string    `json:"name"`    // 接口描述：如 "获取用户列表"
	Method  string    `json:"method"`  // HTTP 方法：GET, POST, etc.
	Path    string    `json:"path"`    // 接口路径：如 "/v1/users"
	Ctime   time.Time `json:"ctime"`
	Utime   time.Time `json:"utime"`
}


