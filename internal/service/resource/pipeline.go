package resource

import (
	"context"
	"time"

	"github.com/gotomicro/ego/core/elog"
)

// SyncPipeline 异步任务流，用于优雅组织初始化任务
type SyncPipeline struct {
	ctx   context.Context
	l     *elog.Component
	tasks []struct {
		name string
		fn   func(context.Context) error
	}
}

func (i *Initializer) NewPipeline(ctx context.Context) *SyncPipeline {
	return &SyncPipeline{
		ctx: ctx,
		l:   i.logger,
	}
}

// Step 添加一个同步步骤
func (p *SyncPipeline) Step(name string, fn func(context.Context) error) *SyncPipeline {
	p.tasks = append(p.tasks, struct {
		name string
		fn   func(context.Context) error
	}{name, fn})
	return p
}

// Run 执行流水线，增加耗时统计与监控可见性
func (p *SyncPipeline) Run() {
	p.l.Info("开始执行内置资产同步流水线", elog.Int("total_tasks", len(p.tasks)))
	totalStart := time.Now()

	for _, task := range p.tasks {
		start := time.Now()
		if err := task.fn(p.ctx); err != nil {
			p.l.Warn("内置资产同步任务执行失败",
				elog.String("task_name", task.name),
				elog.FieldErr(err),
				elog.FieldCost(time.Since(start)),
			)
			continue
		}
		p.l.Info("内置资产同步任务完成",
			elog.String("task_name", task.name),
			elog.FieldCost(time.Since(start)),
		)
	}

	p.l.Info("内置资产同步流水线执行完毕", elog.FieldCost(time.Since(totalStart)))
}
