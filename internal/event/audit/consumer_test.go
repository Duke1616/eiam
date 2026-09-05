package audit

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Duke1616/eiam/internal/domain"
	"github.com/Duke1616/eiam/internal/repository"
	repomocks "github.com/Duke1616/eiam/internal/repository/mocks"
	"github.com/Duke1616/eiam/pkg/gormx"
	"github.com/Duke1616/eiam/pkg/redisx"
	redisxmocks "github.com/Duke1616/eiam/pkg/redisx/mocks"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

func TestConsumer_Flush(t *testing.T) {
	testCases := []struct {
		name       string
		mockRepo   func(ctrl *gomock.Controller) repository.IAuditRepository
		mockQueue  func(ctrl *gomock.Controller) redisx.IStreamQueue[Event]
		mockDL     func(ctrl *gomock.Controller) redisx.IStreamQueue[DeadLetterEvent]
		authItems  []pendingAuthItem
		opItems    []pendingOpItem
	}{
		{
			name: "成功批量持久化认证与操作日志并执行ACK",
			mockRepo: func(ctrl *gomock.Controller) repository.IAuditRepository {
				repo := repomocks.NewMockIAuditRepository(ctrl)
				repo.EXPECT().BatchSaveAuthLogs(gomock.Any(), gomock.Len(1)).
					DoAndReturn(func(ctx context.Context, logs []domain.AuthLog) error {
						assert.Equal(t, true, ctx.Value(gormx.IGNORE_TENANT_KEY))
						return nil
					})
				repo.EXPECT().BatchSaveOperationLogs(gomock.Any(), gomock.Len(1)).
					DoAndReturn(func(ctx context.Context, logs []domain.OperationLog) error {
						assert.Equal(t, true, ctx.Value(gormx.IGNORE_TENANT_KEY))
						return nil
					})
				return repo
			},
			mockQueue: func(ctrl *gomock.Controller) redisx.IStreamQueue[Event] {
				queue := redisxmocks.NewMockIStreamQueue[Event](ctrl)
				queue.EXPECT().Ack(gomock.Any(), StreamName, ConsumerGroup, "1-0").
					Return(nil)
				queue.EXPECT().Ack(gomock.Any(), StreamName, ConsumerGroup, "2-0").
					Return(nil)
				return queue
			},
			mockDL: func(ctrl *gomock.Controller) redisx.IStreamQueue[DeadLetterEvent] {
				return redisxmocks.NewMockIStreamQueue[DeadLetterEvent](ctrl)
			},
			authItems: []pendingAuthItem{{msgID: "1-0", log: domain.AuthLog{ID: 1, Username: "admin"}}},
			opItems:   []pendingOpItem{{msgID: "2-0", log: domain.OperationLog{ID: 2, Action: "user:delete"}}},
		},
		{
			name: "批量落库失败时自动降级单条入库并转储毒丸消息至死信队列",
			mockRepo: func(ctrl *gomock.Controller) repository.IAuditRepository {
				repo := repomocks.NewMockIAuditRepository(ctrl)
				// 1. 整批尝试失败
				repo.EXPECT().BatchSaveAuthLogs(gomock.Any(), gomock.Len(2)).
					Return(errors.New("batch insert syntax error"))

				// 2. 降级模式：第 1 条正常入库
				repo.EXPECT().BatchSaveAuthLogs(gomock.Any(), gomock.Len(1)).
					Return(nil)

				// 3. 降级模式：第 2 条毒丸消息入库再次失败，触发转储死信
				repo.EXPECT().BatchSaveAuthLogs(gomock.Any(), gomock.Len(1)).
					Return(errors.New("poison pill sql error"))
				return repo
			},
			mockQueue: func(ctrl *gomock.Controller) redisx.IStreamQueue[Event] {
				queue := redisxmocks.NewMockIStreamQueue[Event](ctrl)
				// 两条消息均完成 ACK，避免阻塞队列
				queue.EXPECT().Ack(gomock.Any(), StreamName, ConsumerGroup, "10-1", "10-2").
					Return(nil)
				return queue
			},
			mockDL: func(ctrl *gomock.Controller) redisx.IStreamQueue[DeadLetterEvent] {
				dl := redisxmocks.NewMockIStreamQueue[DeadLetterEvent](ctrl)
				dl.EXPECT().Publish(gomock.Any(), DeadLetterStreamName, gomock.Any(), gomock.Any()).
					Return("dl-1", nil)
				return dl
			},
			authItems: []pendingAuthItem{
				{msgID: "10-1", log: domain.AuthLog{ID: 101, Username: "normal_user"}},
				{msgID: "10-2", log: domain.AuthLog{ID: 102, Username: "bad_user"}},
			},
			opItems: nil,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			c := NewConsumerWithQueue(tc.mockQueue(ctrl), tc.mockDL(ctrl), tc.mockRepo(ctrl))
			buffer := newBatchBuffer(10)
			buffer.authItems = append(buffer.authItems, tc.authItems...)
			buffer.opItems = append(buffer.opItems, tc.opItems...)

			c.flush(buffer)
			assert.True(t, buffer.IsEmpty())
		})
	}
}

func TestConsumer_CollectMessages(t *testing.T) {
	testCases := []struct {
		name          string
		mockRepo      func(ctrl *gomock.Controller) repository.IAuditRepository
		mockDL        func(ctrl *gomock.Controller) redisx.IStreamQueue[DeadLetterEvent]
		messages      []redisx.Message[Event]
		wantAuthCount int
		wantOpCount   int
		wantCorrupted int
	}{
		{
			name: "正确解析强类型认证与操作日志并聚合入缓冲",
			mockRepo: func(ctrl *gomock.Controller) repository.IAuditRepository {
				return repomocks.NewMockIAuditRepository(ctrl)
			},
			mockDL: func(ctrl *gomock.Controller) redisx.IStreamQueue[DeadLetterEvent] {
				return redisxmocks.NewMockIStreamQueue[DeadLetterEvent](ctrl)
			},
			messages: []redisx.Message[Event]{
				{
					ID: "100-0",
					Payload: NewAuthEvent(domain.AuthLog{ID: 1, Username: "user1"}),
				},
				{
					ID: "100-1",
					Payload: NewOperationEvent(domain.OperationLog{ID: 2, Action: "create"}),
				},
			},
			wantAuthCount: 1,
			wantOpCount:   1,
			wantCorrupted: 0,
		},
		{
			name: "遇到反序列化损坏消息转投死信队列记录ID",
			mockRepo: func(ctrl *gomock.Controller) repository.IAuditRepository {
				return repomocks.NewMockIAuditRepository(ctrl)
			},
			mockDL: func(ctrl *gomock.Controller) redisx.IStreamQueue[DeadLetterEvent] {
				dl := redisxmocks.NewMockIStreamQueue[DeadLetterEvent](ctrl)
				dl.EXPECT().Publish(gomock.Any(), DeadLetterStreamName, gomock.Any(), gomock.Any()).
					Return("dl-2", nil)
				return dl
			},
			messages: []redisx.Message[Event]{
				{
					ID:  "100-2",
					Err: errors.New("反序列化消息载荷失败: syntax error"),
				},
			},
			wantAuthCount: 0,
			wantOpCount:   0,
			wantCorrupted: 1,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			queue := redisxmocks.NewMockIStreamQueue[Event](ctrl)
			c := NewConsumerWithQueue(queue, tc.mockDL(ctrl), tc.mockRepo(ctrl))
			buffer := newBatchBuffer(10)

			c.collectMessages(context.Background(), tc.messages, buffer)

			assert.Equal(t, tc.wantAuthCount, len(buffer.authItems))
			assert.Equal(t, tc.wantOpCount, len(buffer.opItems))
			assert.Equal(t, tc.wantCorrupted, len(buffer.corruptedMsgIDs))
		})
	}
}

func TestConsumer_ClaimPending(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	repo := repomocks.NewMockIAuditRepository(ctrl)
	queue := redisxmocks.NewMockIStreamQueue[Event](ctrl)
	dl := redisxmocks.NewMockIStreamQueue[DeadLetterEvent](ctrl)

	queue.EXPECT().AutoClaim(gomock.Any(), StreamName, ConsumerGroup, gomock.Any(), time.Minute, "0-0", int64(DefaultBatchSize)).
		Return([]redisx.Message[Event]{
			{
				ID:      "200-0",
				Payload: NewAuthEvent(domain.AuthLog{ID: 88, Username: "reclaimed"}),
			},
		}, "0-0", nil)

	c := NewConsumerWithQueue(queue, dl, repo)
	buffer := newBatchBuffer(10)
	c.claimPending(context.Background(), buffer)

	assert.Equal(t, 1, len(buffer.authItems))
	assert.Equal(t, "200-0", buffer.authItems[0].msgID)
}
