package domain

// TenantKey 租户鉴权密钥领域模型
type TenantKey struct {
	ID          int64  `json:"id"`
	TenantID    int64  `json:"tenant_id"`
	AccessKey   string `json:"access_key"`
	SecretKey   string `json:"-"` // 敏感凭证，JSON 序列化时隐藏
	Status      int    `json:"status"`
	Description string `json:"description"`
	Ctime       int64  `json:"ctime"`
	Utime       int64  `json:"utime"`
}
