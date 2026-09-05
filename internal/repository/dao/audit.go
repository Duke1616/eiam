package dao

import (
	"context"

	"github.com/Duke1616/eiam/internal/domain"
	"gorm.io/gorm"
)

// AuditAuthLog 认证审计 GORM 实体
type AuditAuthLog struct {
	Id         int64  `gorm:"primaryKey;autoIncrement;comment:'自增主键ID'"`
	TenantId   int64  `gorm:"column:tenant_id;index:idx_tenant_ctime,priority:1;comment:'租户ID'"`
	UserId     int64  `gorm:"column:user_id;default:0;comment:'用户ID'"`
	Username   string `gorm:"column:username;type:varchar(64);not null;index:idx_username_ctime,priority:1;comment:'登录账号'"`
	AuthType   string `gorm:"column:auth_type;type:varchar(32);not null;comment:'认证方式: local, ldap, oidc, passkey 等'"`
	Status     string `gorm:"column:status;type:varchar(16);not null;comment:'认证状态: SUCCESS, FAIL, LOCKED'"`
	FailReason string `gorm:"column:fail_reason;type:varchar(255);comment:'认证失败原因'"`
	ClientIp   string `gorm:"column:client_ip;type:varchar(64);comment:'客户端IP地址'"`
	UserAgent  string `gorm:"column:user_agent;type:varchar(512);comment:'客户端终端UA信息'"`
	Ctime      int64  `gorm:"column:ctime;index:idx_tenant_ctime,priority:2;index:idx_username_ctime,priority:2;comment:'创建时间戳(毫秒)'"`
}

// TableName 指定认证审计表表名
func (AuditAuthLog) TableName() string {
	return "audit_auth_logs"
}

// AuditOperationLog 操作审计 GORM 实体 (Subject -> Action -> Resource)
type AuditOperationLog struct {
	Id           int64  `gorm:"primaryKey;autoIncrement;comment:'自增主键ID'"`
	TenantId     int64  `gorm:"column:tenant_id;index:idx_tenant_op_ctime,priority:1;index:idx_tenant_svc_ctime,priority:1;comment:'租户ID'"`
	Service      string `gorm:"column:service;type:varchar(64);not null;default:'';index:idx_tenant_svc_ctime,priority:2;comment:'所属业务服务标识'"`
	OperatorId   int64  `gorm:"column:operator_id;not null;comment:'操作人用户ID'"`
	OperatorName string `gorm:"column:operator_name;type:varchar(64);not null;comment:'操作人账号名称'"`
	Module       string `gorm:"column:module;type:varchar(64);not null;index:idx_module_action,priority:1;comment:'业务模块标识'"`
	Action       string `gorm:"column:action;type:varchar(64);not null;index:idx_module_action,priority:2;comment:'操作动作: create, update, delete 等'"`
	ResourceId   string `gorm:"column:resource_id;type:varchar(64);comment:'被操作资源的唯一标识'"`
	ResourceName string `gorm:"column:resource_name;type:varchar(128);comment:'资源或操作友好中文名称'"`
	ResourceUrn  string `gorm:"column:resource_urn;type:varchar(255);comment:'统一资源 URN 标识'"`
	BeforeState  string `gorm:"column:before_state;type:text;comment:'变更前状态快照'"`
	AfterState   string `gorm:"column:after_state;type:text;comment:'变更后状态或入参快照'"`
	Status       string `gorm:"column:status;type:varchar(16);not null;comment:'操作执行状态: SUCCESS, FAIL'"`
	FailReason   string `gorm:"column:fail_reason;type:varchar(255);comment:'操作失败错误信息'"`
	ClientIp     string `gorm:"column:client_ip;type:varchar(64);comment:'操作客户端IP'"`
	UserAgent    string `gorm:"column:user_agent;type:varchar(512);comment:'操作终端UA'"`
	Ctime        int64  `gorm:"column:ctime;index:idx_tenant_op_ctime,priority:2;index:idx_module_action,priority:3;index:idx_tenant_svc_ctime,priority:3;comment:'操作时间戳(毫秒)'"`
}

// TableName 指定操作审计表表名
func (AuditOperationLog) TableName() string {
	return "audit_operation_logs"
}

// IAuditDAO 审计日志数据访问接口
//
//go:generate mockgen -package=daomocks -destination=./mocks/audit.mock.go github.com/Duke1616/eiam/internal/repository/dao IAuditDAO
type IAuditDAO interface {
	// BatchInsertAuthLogs 批量写入认证审计日志
	BatchInsertAuthLogs(ctx context.Context, logs []AuditAuthLog) error
	// BatchInsertOperationLogs 批量写入操作审计日志
	BatchInsertOperationLogs(ctx context.Context, logs []AuditOperationLog) error
	// ListAuthLogs 条件分页检索认证审计日志
	ListAuthLogs(ctx context.Context, filter domain.AuthLogFilter, offset, limit int) ([]AuditAuthLog, int64, error)
	// ListOperationLogs 条件分页检索管理操作审计日志
	ListOperationLogs(ctx context.Context, filter domain.OperationLogFilter, offset, limit int) ([]AuditOperationLog, int64, error)
}

type auditDAO struct {
	db *gorm.DB
}

// NewAuditDAO 构建审计数据访问实例
func NewAuditDAO(db *gorm.DB) IAuditDAO {
	return &auditDAO{db: db}
}

// BatchInsertAuthLogs 批量写入认证审计日志，使用 CreateInBatches 批量执行降低事务开销
func (d *auditDAO) BatchInsertAuthLogs(ctx context.Context, logs []AuditAuthLog) error {
	if len(logs) == 0 {
		return nil
	}
	return d.db.WithContext(ctx).CreateInBatches(logs, 100).Error
}

// BatchInsertOperationLogs 批量写入操作审计日志
func (d *auditDAO) BatchInsertOperationLogs(ctx context.Context, logs []AuditOperationLog) error {
	if len(logs) == 0 {
		return nil
	}
	return d.db.WithContext(ctx).CreateInBatches(logs, 100).Error
}

// ListAuthLogs 条件分页检索认证审计日志
func (d *auditDAO) ListAuthLogs(ctx context.Context, filter domain.AuthLogFilter, offset, limit int) ([]AuditAuthLog, int64, error) {
	var logs []AuditAuthLog
	var total int64

	query := d.db.WithContext(ctx).Model(&AuditAuthLog{})
	if filter.Username != "" {
		query = query.Where("username LIKE ?", "%"+filter.Username+"%")
	}
	if filter.AuthType != "" {
		query = query.Where("auth_type = ?", filter.AuthType)
	}
	if filter.Status != "" {
		query = query.Where("status = ?", filter.Status)
	}
	if filter.StartTime > 0 {
		query = query.Where("ctime >= ?", filter.StartTime)
	}
	if filter.EndTime > 0 {
		query = query.Where("ctime <= ?", filter.EndTime)
	}

	if err := query.Count(&total).Error; err != nil {
		return nil, 0, err
	}

	err := query.Order("ctime DESC").Offset(offset).Limit(limit).Find(&logs).Error
	return logs, total, err
}

// ListOperationLogs 条件分页检索管理操作审计日志
func (d *auditDAO) ListOperationLogs(ctx context.Context, filter domain.OperationLogFilter, offset, limit int) ([]AuditOperationLog, int64, error) {
	var logs []AuditOperationLog
	var total int64

	query := d.db.WithContext(ctx).Model(&AuditOperationLog{})
	if filter.Service != "" {
		query = query.Where("service = ?", filter.Service)
	}
	if filter.OperatorName != "" {
		query = query.Where("operator_name LIKE ?", "%"+filter.OperatorName+"%")
	}
	if filter.Module != "" {
		query = query.Where("module = ?", filter.Module)
	}
	if filter.Action != "" {
		query = query.Where("action REGEXP ?", filter.Action)
	}
	if filter.Status != "" {
		query = query.Where("status = ?", filter.Status)
	}
	if filter.StartTime > 0 {
		query = query.Where("ctime >= ?", filter.StartTime)
	}
	if filter.EndTime > 0 {
		query = query.Where("ctime <= ?", filter.EndTime)
	}

	if err := query.Count(&total).Error; err != nil {
		return nil, 0, err
	}

	err := query.Order("ctime DESC").Offset(offset).Limit(limit).Find(&logs).Error
	return logs, total, err
}
