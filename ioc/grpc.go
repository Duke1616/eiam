package ioc

import (
	tenantv1 "github.com/Duke1616/eiam/api/proto/gen/eiam/tenant/v1"
	userv1 "github.com/Duke1616/eiam/api/proto/gen/eiam/user/v1"
	grpcpkg "github.com/Duke1616/etask/pkg/grpc"
	registrysdk "github.com/Duke1616/etask/pkg/grpc/registry"

	"github.com/spf13/viper"
)

func InitGrpcServer(
	registry registrysdk.Registry,
	userServer userv1.UserServiceServer,
	tenantServer tenantv1.TenantServiceServer,
) *grpcpkg.Server {
	var cfg grpcpkg.ServerConfig
	if err := viper.UnmarshalKey("grpc.server.eiam", &cfg); err != nil {
		panic(err)
	}

	server := grpcpkg.NewServer(cfg, registry, grpcpkg.WithJWTAuth(cfg.AuthToken))

	userv1.RegisterUserServiceServer(server, userServer)
	tenantv1.RegisterTenantServiceServer(server, tenantServer)
	return server
}
