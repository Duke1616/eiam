package domain

const (
	// AuthStatusSuccess 认证成功
	AuthStatusSuccess = "SUCCESS"
	// AuthStatusFailed 认证失败
	AuthStatusFailed = "FAIL"
	// AuthStatusLocked 账号锁定
	AuthStatusLocked = "LOCKED"

	// OpStatusSuccess 操作成功
	OpStatusSuccess = "SUCCESS"
	// OpStatusFailed 操作失败
	OpStatusFailed = "FAIL"
)

// AuthLog 认证安全审计实体
type AuthLog struct {
	ID         int64  `json:"id"`
	TenantID   int64  `json:"tenant_id"`
	UserID     int64  `json:"user_id"`
	Username   string `json:"username"`
	AuthType   string `json:"auth_type"`   // password, ldap, oidc, passkey
	Status     string `json:"status"`      // SUCCESS, FAIL, LOCKED
	FailReason string `json:"fail_reason"` // 失败原因（如密码错误、MFA失效）
	ClientIP   string `json:"client_ip"`
	UserAgent  string `json:"user_agent"`
	Ctime      int64  `json:"ctime"` // 毫秒时间戳
}

// OperationLog 管理操作审计实体 (遵循 IAM 三元组模型: Subject -> Action -> Resource)
type OperationLog struct {
	ID           int64  `json:"id"`
	TenantID     int64  `json:"tenant_id"`
	Service      string `json:"service"`       // 所属服务: eiam, ecmdb, etask 等
	OperatorID   int64  `json:"operator_id"`
	OperatorName string `json:"operator_name"`
	Module       string `json:"module"`        // 业务模块: user, role, group, tenant, policy, department 等
	Action       string `json:"action"`        // 操作动作: create, update, delete, assign 等
	ResourceID   string `json:"resource_id"`   // 被操作资源的唯一标识 (如用户ID、角色ID、URL路径参数 :id)
	ResourceName string `json:"resource_name"` // 资源友好名称 (如“创建部门”、“超级管理员角色”)
	ResourceURN  string `json:"resource_urn"`  // 统一资源 URN 标识 (如: urn:iam:api:iam:post:/api/department/create)
	BeforeState  string `json:"before_state"`  // 变更前状态快照
	AfterState   string `json:"after_state"`   // 变更后状态快照或入参摘要
	Status       string `json:"status"`        // SUCCESS, FAIL
	FailReason   string `json:"fail_reason"`   // 失败错误信息
	ClientIP     string `json:"client_ip"`
	UserAgent    string `json:"user_agent"`
	Ctime        int64  `json:"ctime"` // 毫秒时间戳
}

// AuthLogFilter 认证审计查询过滤条件
type AuthLogFilter struct {
	Username  string `json:"username"`
	AuthType  string `json:"auth_type"`
	Status    string `json:"status"`
	StartTime int64  `json:"start_time"`
	EndTime   int64  `json:"end_time"`
}

// OperationLogFilter 操作审计查询过滤条件 (与前端检索面板严格对齐)
type OperationLogFilter struct {
	Service      string `json:"service"`
	OperatorName string `json:"operator_name"`
	Module       string `json:"module"`
	Action       string `json:"action"`
	Status       string `json:"status"`
	StartTime    int64  `json:"start_time"`
	EndTime      int64  `json:"end_time"`
}
