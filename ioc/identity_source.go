package ioc

import (
	"github.com/Duke1616/ecmdb/pkg/cryptox"
	"github.com/Duke1616/eiam/internal/repository"
	"github.com/Duke1616/eiam/internal/service/identity_source"
)

func InitIdentitySourceService(repo repository.IIdentitySourceRepository, cm *cryptox.CryptoManager) identity_source.IService {
	return identity_source.NewService(repo, identity_source.NewOidcService(), cm)
}
