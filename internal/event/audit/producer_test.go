package audit

import (
	"context"
	"errors"
	"testing"

	"github.com/Duke1616/eiam/internal/domain"
	"github.com/Duke1616/eiam/pkg/redisx"
	redisxmocks "github.com/Duke1616/eiam/pkg/redisx/mocks"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

func TestProducer_RecordAuth(t *testing.T) {
	testCases := []struct {
		name    string
		mock    func(ctrl *gomock.Controller) redisx.IStreamQueue[Event]
		log     domain.AuthLog
		wantErr error
	}{
		{
			name: "成功记录认证日志到流",
			mock: func(ctrl *gomock.Controller) redisx.IStreamQueue[Event] {
				queue := redisxmocks.NewMockIStreamQueue[Event](ctrl)
				queue.EXPECT().Publish(gomock.Any(), StreamName, gomock.Any(), gomock.Any()).
					Return("1-0", nil)
				return queue
			},
			log: domain.AuthLog{
				TenantID: 1,
				Username: "admin",
				Status:   domain.AuthStatusSuccess,
			},
			wantErr: nil,
		},
		{
			name: "底层消息流发布失败向上抛错",
			mock: func(ctrl *gomock.Controller) redisx.IStreamQueue[Event] {
				queue := redisxmocks.NewMockIStreamQueue[Event](ctrl)
				queue.EXPECT().Publish(gomock.Any(), StreamName, gomock.Any(), gomock.Any()).
					Return("", errors.New("redis connection refused"))
				return queue
			},
			log: domain.AuthLog{
				TenantID: 1,
				Username: "admin",
				Status:   domain.AuthStatusSuccess,
			},
			wantErr: errors.New("投递审计事件失败: redis connection refused"),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			p := NewProducerWithQueue(tc.mock(ctrl))
			err := p.RecordAuth(context.Background(), tc.log)
			if tc.wantErr != nil {
				assert.EqualError(t, err, tc.wantErr.Error())
				return
			}
			assert.NoError(t, err)
		})
	}
}

func TestProducer_RecordOperation(t *testing.T) {
	testCases := []struct {
		name    string
		mock    func(ctrl *gomock.Controller) redisx.IStreamQueue[Event]
		log     domain.OperationLog
		wantErr error
	}{
		{
			name: "成功记录业务操作日志到流",
			mock: func(ctrl *gomock.Controller) redisx.IStreamQueue[Event] {
				queue := redisxmocks.NewMockIStreamQueue[Event](ctrl)
				queue.EXPECT().Publish(gomock.Any(), StreamName, gomock.Any(), gomock.Any()).
					Return("2-0", nil)
				return queue
			},
			log: domain.OperationLog{
				TenantID:     1,
				OperatorID:   1,
				OperatorName: "superadmin",
				Action:       "role:assign",
				ResourceURN:  "urn:iam:role:10",
				Status:       domain.OpStatusSuccess,
			},
			wantErr: nil,
		},
		{
			name: "流队列写入超时报错",
			mock: func(ctrl *gomock.Controller) redisx.IStreamQueue[Event] {
				queue := redisxmocks.NewMockIStreamQueue[Event](ctrl)
				queue.EXPECT().Publish(gomock.Any(), StreamName, gomock.Any(), gomock.Any()).
					Return("", errors.New("timeout"))
				return queue
			},
			log: domain.OperationLog{
				TenantID: 1,
			},
			wantErr: errors.New("投递审计事件失败: timeout"),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			p := NewProducerWithQueue(tc.mock(ctrl))
			err := p.RecordOperation(context.Background(), tc.log)
			if tc.wantErr != nil {
				assert.EqualError(t, err, tc.wantErr.Error())
				return
			}
			assert.NoError(t, err)
		})
	}
}
