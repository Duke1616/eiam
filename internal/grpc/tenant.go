package grpc

import (
	"context"

	tenantv1 "github.com/Duke1616/eiam/api/proto/gen/eiam/tenant/v1"
	"github.com/Duke1616/eiam/internal/service/tenant"
)

type TenantServiceServer struct {
	tenantv1.UnimplementedTenantServiceServer
	svc tenant.ITenantKeyService
}

func NewTenantServiceServer(svc tenant.ITenantKeyService) tenantv1.TenantServiceServer {
	return &TenantServiceServer{svc: svc}
}

// Verify 验证 AccessKey / SecretKey 并返回对应的租户 ID
func (s *TenantServiceServer) Verify(ctx context.Context, req *tenantv1.VerifyRequest) (*tenantv1.VerifyResponse, error) {
	tenantID, err := s.svc.VerifyKey(ctx, req.GetAccessKey(), req.GetSecretKey())
	if err != nil {
		return nil, err
	}
	return &tenantv1.VerifyResponse{
		TenantId: tenantID,
	}, nil
}
