package ioc

import (
	auditevt "github.com/Duke1616/eiam/internal/event/audit"
	"github.com/Duke1616/eiam/internal/service/discovery"
)

// InitTasks 汇总系统中所有的后台长任务 (实现 Task 接口)
func InitTasks(t1 *discovery.Worker, t2 *auditevt.Consumer) []Task {
	return []Task{
		t1,
		t2,
	}
}
