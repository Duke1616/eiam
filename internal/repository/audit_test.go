package repository

import (
	"context"
	"errors"
	"testing"

	"github.com/Duke1616/eiam/internal/domain"
	"github.com/Duke1616/eiam/internal/repository/dao"
	daomocks "github.com/Duke1616/eiam/internal/repository/dao/mocks"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

func TestAuditRepository_BatchSaveAuthLogs(t *testing.T) {
	testCases := []struct {
		name    string
		mock    func(ctrl *gomock.Controller) dao.IAuditDAO
		logs    []domain.AuthLog
		wantErr error
	}{
		{
			name: "成功批量保存认证日志",
			mock: func(ctrl *gomock.Controller) dao.IAuditDAO {
				d := daomocks.NewMockIAuditDAO(ctrl)
				d.EXPECT().BatchInsertAuthLogs(gomock.Any(), gomock.Len(1)).Return(nil)
				return d
			},
			logs: []domain.AuthLog{
				{
					TenantID: 1,
					UserID:   10,
					Username: "alice",
					Status:   domain.AuthStatusSuccess,
				},
			},
			wantErr: nil,
		},
		{
			name: "空切片直接跳过入库",
			mock: func(ctrl *gomock.Controller) dao.IAuditDAO {
				return daomocks.NewMockIAuditDAO(ctrl)
			},
			logs:    []domain.AuthLog{},
			wantErr: nil,
		},
		{
			name: "DAO层批量插入抛错",
			mock: func(ctrl *gomock.Controller) dao.IAuditDAO {
				d := daomocks.NewMockIAuditDAO(ctrl)
				d.EXPECT().BatchInsertAuthLogs(gomock.Any(), gomock.Len(1)).Return(errors.New("db error"))
				return d
			},
			logs: []domain.AuthLog{
				{TenantID: 1, Username: "bob"},
			},
			wantErr: errors.New("db error"),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			repo := NewAuditRepository(tc.mock(ctrl))
			err := repo.BatchSaveAuthLogs(context.Background(), tc.logs)
			if tc.wantErr != nil {
				assert.EqualError(t, err, tc.wantErr.Error())
				return
			}
			assert.NoError(t, err)
		})
	}
}

func TestAuditRepository_BatchSaveOperationLogs(t *testing.T) {
	testCases := []struct {
		name    string
		mock    func(ctrl *gomock.Controller) dao.IAuditDAO
		logs    []domain.OperationLog
		wantErr error
	}{
		{
			name: "成功批量保存操作审计日志",
			mock: func(ctrl *gomock.Controller) dao.IAuditDAO {
				d := daomocks.NewMockIAuditDAO(ctrl)
				d.EXPECT().BatchInsertOperationLogs(gomock.Any(), gomock.Len(1)).Return(nil)
				return d
			},
			logs: []domain.OperationLog{
				{
					TenantID:     1,
					OperatorID:   1,
					OperatorName: "admin",
					Action:       "user:create",
					ResourceURN:  "urn:iam:user:2",
					Status:       domain.OpStatusSuccess,
				},
			},
			wantErr: nil,
		},
		{
			name: "空切片直接返回无错误",
			mock: func(ctrl *gomock.Controller) dao.IAuditDAO {
				return daomocks.NewMockIAuditDAO(ctrl)
			},
			logs:    []domain.OperationLog{},
			wantErr: nil,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			repo := NewAuditRepository(tc.mock(ctrl))
			err := repo.BatchSaveOperationLogs(context.Background(), tc.logs)
			if tc.wantErr != nil {
				assert.EqualError(t, err, tc.wantErr.Error())
				return
			}
			assert.NoError(t, err)
		})
	}
}

func TestAuditRepository_ListAuthLogs(t *testing.T) {
	testCases := []struct {
		name      string
		mock      func(ctrl *gomock.Controller) dao.IAuditDAO
		filter    domain.AuthLogFilter
		offset    int
		limit     int
		wantTotal int64
		wantLen   int
		wantErr   error
	}{
		{
			name: "成功分页检索认证日志并完成实体映射",
			mock: func(ctrl *gomock.Controller) dao.IAuditDAO {
				d := daomocks.NewMockIAuditDAO(ctrl)
				d.EXPECT().ListAuthLogs(gomock.Any(), domain.AuthLogFilter{Username: "alice"}, 0, 10).
					Return([]dao.AuditAuthLog{
						{
							Id:       1,
							TenantId: 1,
							UserId:   100,
							Username: "alice",
							Status:   "SUCCESS",
							ClientIp: "127.0.0.1",
						},
					}, int64(1), nil)
				return d
			},
			filter:    domain.AuthLogFilter{Username: "alice"},
			offset:    0,
			limit:     10,
			wantTotal: 1,
			wantLen:   1,
			wantErr:   nil,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			repo := NewAuditRepository(tc.mock(ctrl))
			logs, total, err := repo.ListAuthLogs(context.Background(), tc.filter, tc.offset, tc.limit)
			if tc.wantErr != nil {
				assert.EqualError(t, err, tc.wantErr.Error())
				return
			}
			assert.NoError(t, err)
			assert.Equal(t, tc.wantTotal, total)
			assert.Equal(t, tc.wantLen, len(logs))
			if len(logs) > 0 {
				assert.Equal(t, int64(1), logs[0].ID)
				assert.Equal(t, "alice", logs[0].Username)
				assert.Equal(t, "127.0.0.1", logs[0].ClientIP)
			}
		})
	}
}

func TestAuditRepository_ListOperationLogs(t *testing.T) {
	testCases := []struct {
		name      string
		mock      func(ctrl *gomock.Controller) dao.IAuditDAO
		filter    domain.OperationLogFilter
		offset    int
		limit     int
		wantTotal int64
		wantLen   int
		wantErr   error
	}{
		{
			name: "成功分页检索操作日志并完成实体映射",
			mock: func(ctrl *gomock.Controller) dao.IAuditDAO {
				d := daomocks.NewMockIAuditDAO(ctrl)
				d.EXPECT().ListOperationLogs(gomock.Any(), domain.OperationLogFilter{OperatorName: "admin"}, 0, 10).
					Return([]dao.AuditOperationLog{
						{
							Id:           1,
							TenantId:     1,
							OperatorId:   10,
							OperatorName: "admin",
							Action:       "user:create",
							ResourceId:   "101",
							ResourceUrn:  "urn:iam:user:101",
							Status:       "SUCCESS",
							ClientIp:     "192.168.1.1",
						},
					}, int64(1), nil)
				return d
			},
			filter:    domain.OperationLogFilter{OperatorName: "admin"},
			offset:    0,
			limit:     10,
			wantTotal: 1,
			wantLen:   1,
			wantErr:   nil,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			repo := NewAuditRepository(tc.mock(ctrl))
			logs, total, err := repo.ListOperationLogs(context.Background(), tc.filter, tc.offset, tc.limit)
			if tc.wantErr != nil {
				assert.EqualError(t, err, tc.wantErr.Error())
				return
			}
			assert.NoError(t, err)
			assert.Equal(t, tc.wantTotal, total)
			assert.Equal(t, tc.wantLen, len(logs))
			if len(logs) > 0 {
				assert.Equal(t, int64(1), logs[0].ID)
				assert.Equal(t, "admin", logs[0].OperatorName)
				assert.Equal(t, "urn:iam:user:101", logs[0].ResourceURN)
				assert.Equal(t, "192.168.1.1", logs[0].ClientIP)
			}
		})
	}
}
