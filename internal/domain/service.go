package domain

// Service 逻辑服务定义 (Namespace)
type Service struct {
	ID          int64  `json:"id"`
	Code        string `json:"code"`        // 唯一标识，如 "iam"
	Name        string `json:"name"`        // 友好显示名，如 "身份访问管理"
	Description string `json:"description"` // 描述
	Ctime       int64  `json:"ctime"`
	Utime       int64  `json:"utime"`
}
