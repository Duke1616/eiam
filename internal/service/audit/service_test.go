package audit

import (
	"context"
	"errors"
	"testing"

	"github.com/Duke1616/eiam/internal/domain"
	"github.com/Duke1616/eiam/internal/repository"
	repomocks "github.com/Duke1616/eiam/internal/repository/mocks"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

func TestAuditService_ListAuthLogs(t *testing.T) {
	testCases := []struct {
		name      string
		mock      func(ctrl *gomock.Controller) repository.IAuditRepository
		filter    domain.AuthLogFilter
		offset    int
		limit     int
		wantLogs  []domain.AuthLog
		wantTotal int64
		wantErr   error
	}{
		{
			name: "成功分页查询认证日志",
			mock: func(ctrl *gomock.Controller) repository.IAuditRepository {
				repo := repomocks.NewMockIAuditRepository(ctrl)
				repo.EXPECT().ListAuthLogs(gomock.Any(), domain.AuthLogFilter{Username: "admin"}, 0, 10).
					Return([]domain.AuthLog{
						{ID: 1, TenantID: 1, Username: "admin", Status: domain.AuthStatusSuccess},
					}, int64(1), nil)
				return repo
			},
			filter:    domain.AuthLogFilter{Username: "admin"},
			offset:    0,
			limit:     10,
			wantLogs:  []domain.AuthLog{{ID: 1, TenantID: 1, Username: "admin", Status: domain.AuthStatusSuccess}},
			wantTotal: 1,
			wantErr:   nil,
		},
		{
			name: "底层仓储返回数据库错误",
			mock: func(ctrl *gomock.Controller) repository.IAuditRepository {
				repo := repomocks.NewMockIAuditRepository(ctrl)
				repo.EXPECT().ListAuthLogs(gomock.Any(), domain.AuthLogFilter{Username: "admin"}, 0, 10).
					Return(nil, int64(0), errors.New("db query error"))
				return repo
			},
			filter:    domain.AuthLogFilter{Username: "admin"},
			offset:    0,
			limit:     10,
			wantLogs:  nil,
			wantTotal: 0,
			wantErr:   errors.New("db query error"),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			svc := NewService(tc.mock(ctrl))
			logs, total, err := svc.ListAuthLogs(context.Background(), tc.filter, tc.offset, tc.limit)

			if tc.wantErr != nil {
				assert.EqualError(t, err, tc.wantErr.Error())
				return
			}
			assert.NoError(t, err)
			assert.Equal(t, tc.wantTotal, total)
			assert.Equal(t, tc.wantLogs, logs)
		})
	}
}

func TestAuditService_ListOperationLogs(t *testing.T) {
	testCases := []struct {
		name      string
		mock      func(ctrl *gomock.Controller) repository.IAuditRepository
		filter    domain.OperationLogFilter
		offset    int
		limit     int
		wantLogs  []domain.OperationLog
		wantTotal int64
		wantErr   error
	}{
		{
			name: "成功分页查询操作日志",
			mock: func(ctrl *gomock.Controller) repository.IAuditRepository {
				repo := repomocks.NewMockIAuditRepository(ctrl)
				repo.EXPECT().ListOperationLogs(gomock.Any(), domain.OperationLogFilter{Action: "user:create"}, 0, 20).
					Return([]domain.OperationLog{
						{ID: 101, TenantID: 1, OperatorID: 1, OperatorName: "superadmin", Action: "user:create", ResourceURN: "urn:iam:user:101"},
					}, int64(1), nil)
				return repo
			},
			filter:    domain.OperationLogFilter{Action: "user:create"},
			offset:    0,
			limit:     20,
			wantLogs: []domain.OperationLog{
				{ID: 101, TenantID: 1, OperatorID: 1, OperatorName: "superadmin", Action: "user:create", ResourceURN: "urn:iam:user:101"},
			},
			wantTotal: 1,
			wantErr:   nil,
		},
		{
			name: "底层仓储返回错误透传",
			mock: func(ctrl *gomock.Controller) repository.IAuditRepository {
				repo := repomocks.NewMockIAuditRepository(ctrl)
				repo.EXPECT().ListOperationLogs(gomock.Any(), domain.OperationLogFilter{Action: "user:create"}, 0, 20).
					Return(nil, int64(0), errors.New("timeout"))
				return repo
			},
			filter:    domain.OperationLogFilter{Action: "user:create"},
			offset:    0,
			limit:     20,
			wantLogs:  nil,
			wantTotal: 0,
			wantErr:   errors.New("timeout"),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			svc := NewService(tc.mock(ctrl))
			logs, total, err := svc.ListOperationLogs(context.Background(), tc.filter, tc.offset, tc.limit)

			if tc.wantErr != nil {
				assert.EqualError(t, err, tc.wantErr.Error())
				return
			}
			assert.NoError(t, err)
			assert.Equal(t, tc.wantTotal, total)
			assert.Equal(t, tc.wantLogs, logs)
		})
	}
}
