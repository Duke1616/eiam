package user

import (
	"github.com/Duke1616/eiam/internal/domain"
	"github.com/ecodeclub/ekit/slice"
)

func (req SignupRequest) ToDomain() domain.User {
	return domain.User{
		Username: req.Username,
		Password: req.Password,
		Email:    req.Email,
		Profile: domain.UserProfile{
			Nickname: req.Nickname,
			Avatar:   req.Avatar,
			JobTitle: req.JobTitle,
		},
	}
}

func ToUserVO(u domain.User) User {
	identities := slice.Map(u.Identities, func(idx int, src domain.UserIdentity) Identity {
		return Identity{
			Provider:   src.Provider,
			LdapInfo:   LdapInfo{DN: src.LdapInfo.DN},
			WechatInfo: WechatInfo{UserID: src.WechatInfo.UserID},
			FeishuInfo: FeishuInfo{
				OpenID: src.FeishuInfo.OpenID,
				UserID: src.FeishuInfo.UserID,
			},
		}
	})

	return User{
		ID:         u.ID,
		Username:   u.Username,
		Email:      u.Email,
		Nickname:   u.Profile.Nickname,
		Avatar:     u.Profile.Avatar,
		JobTitle:   u.Profile.JobTitle,
		Identities: identities,
	}
}

func ToTenantVOs(ts []domain.Tenant) []Tenant {
	return slice.Map(ts, func(idx int, src domain.Tenant) Tenant {
		return Tenant{
			ID:     src.ID,
			Name:   src.Name,
			Code:   src.Code,
			Domain: src.Domain,
		}
	})
}
