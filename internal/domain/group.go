package domain

// Group 用户组（权限组）领域模型
type Group struct {
	ID    int64  `json:"id"`
	Name  string `json:"name"`
	Code  string `json:"code"`
	Desc  string `json:"desc"`
	Ctime int64  `json:"ctime"`
	Utime int64  `json:"utime"`
}
