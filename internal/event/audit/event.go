package audit

import (
	"time"

	"github.com/Duke1616/eiam/internal/domain"
)

const (
	// StreamName 审计日志在 Redis Stream 中的流名称
	StreamName = "eiam:audit:events"
	// ConsumerGroup 审计消费组名称
	ConsumerGroup = "eiam-audit-group"

	// EventTypeAuth 认证日志事件类型
	EventTypeAuth = "AUTH"
	// EventTypeOperation 业务管理操作日志事件类型
	EventTypeOperation = "OPERATION"

	// DefaultBatchSize 消费端批量写入 MySQL 的批次大小阈值
	DefaultBatchSize = 100
	// DefaultFlushInterval 消费端缓冲队列刷新间隔
	DefaultFlushInterval = 500 * time.Millisecond
	// MaxStreamLength Redis Stream 保留的最大消息量 (近似裁剪)
	MaxStreamLength = 50000
	// DeadLetterStreamName 审计死信流名称，用于存放无法正常入库的异常消息
	DeadLetterStreamName = "eiam:audit:dead_letter"
)

// DeadLetterEvent 死信消息包装载荷
type DeadLetterEvent struct {
	OriginalMsgID string `json:"original_msg_id"`
	Reason        string `json:"reason"`
	Payload       string `json:"payload"`
	FailedAt      int64  `json:"failed_at"`
}

// Event 统一审计事件载荷
type Event struct {
	Type         string               `json:"type"`
	AuthLog      *domain.AuthLog      `json:"auth_log,omitempty"`
	OperationLog *domain.OperationLog `json:"operation_log,omitempty"`
	Timestamp    int64                `json:"timestamp"`
}

// NewAuthEvent 构建认证安全审计事件
func NewAuthEvent(log domain.AuthLog) Event {
	if log.Ctime == 0 {
		log.Ctime = time.Now().UnixMilli()
	}
	return Event{
		Type:      EventTypeAuth,
		AuthLog:   &log,
		Timestamp: log.Ctime,
	}
}

// NewOperationEvent 构建业务操作审计事件
func NewOperationEvent(log domain.OperationLog) Event {
	if log.Ctime == 0 {
		log.Ctime = time.Now().UnixMilli()
	}
	return Event{
		Type:         EventTypeOperation,
		OperationLog: &log,
		Timestamp:    log.Ctime,
	}
}
