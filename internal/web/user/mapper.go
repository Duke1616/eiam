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
		Ctime:      u.Ctime,
		Utime:      u.Utime,
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

func (req UpdateUserReq) ToDomain() domain.User {
	return domain.User{
		ID:       req.ID,
		Username: req.Username,
		Email:    req.Email,
		Profile: domain.UserProfile{
			Nickname: req.Nickname,
			Avatar:   req.Avatar,
			JobTitle: req.JobTitle,
		},
	}
}

func (u User) ToDomain() domain.User {
	identities := slice.Map(u.Identities, func(idx int, src Identity) domain.UserIdentity {
		return domain.UserIdentity{
			Provider:   src.Provider,
			LdapInfo:   domain.LdapInfo{DN: src.LdapInfo.DN},
			WechatInfo: domain.WechatInfo{UserID: src.WechatInfo.UserID},
			FeishuInfo: domain.FeishuInfo{
				OpenID: src.FeishuInfo.OpenID,
				UserID: src.FeishuInfo.UserID,
			},
		}
	})

	return domain.User{
		ID:       u.ID,
		Username: u.Username,
		Email:    u.Email,
		Ctime:    u.Ctime,
		Utime:    u.Utime,
		Profile: domain.UserProfile{
			Nickname: u.Nickname,
			Avatar:   u.Avatar,
			JobTitle: u.JobTitle,
		},
		Identities: identities,
	}
}
