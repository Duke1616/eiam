package user

import (
	"github.com/Duke1616/eiam/internal/domain"
	"github.com/samber/lo"
)

func (req SignupRequest) ToDomain() domain.User {
	return domain.User{
		Username: req.Username,
		Password: req.Password,
		Email:    req.Email,
		Status:   domain.ParseStatus(req.Status),
		Profile: domain.UserProfile{
			Nickname: req.Nickname,
			Avatar:   req.Avatar,
			JobTitle: req.JobTitle,
			Phone:    req.Phone,
		},
	}
}

func ToUserVO(u domain.User) User {
	identities := lo.Map(u.Identities, func(src domain.UserIdentity, _ int) Identity {
		return Identity{
			Provider:   src.Provider,
			LdapInfo:   LdapInfo{DN: src.LdapInfo.DN},
			WechatInfo: WechatInfo{UserID: src.WechatInfo.UserID},
			FeishuInfo: FeishuInfo{
				OpenID:  src.FeishuInfo.OpenID,
				UnionID: src.FeishuInfo.UnionID,
				UserID:  src.FeishuInfo.UserID,
			},
			PasskeyInfo: PasskeyInfo{
				Nickname:  src.PasskeyInfo.Nickname,
				SignCount: src.PasskeyInfo.SignCount,
			},
		}
	})

	return User{
		ID:          u.ID,
		Username:    u.Username,
		Email:       u.Email,
		Nickname:    u.Profile.Nickname,
		Avatar:      u.Profile.Avatar,
		JobTitle:    u.Profile.JobTitle,
		Phone:       u.Profile.Phone,
		Status:      u.Status.String(),
		Source:      u.Source.String(),
		Ctime:       u.Ctime,
		Utime:       u.Utime,
		LastLoginAt: u.LastLoginAt,
		MfaType:     u.MfaType,
		MfaBound:    u.MfaType != "",
		Identities:  identities,
	}
}

func ToTenantVOs(ts []domain.Tenant) []Tenant {
	return lo.Map(ts, func(src domain.Tenant, _ int) Tenant {
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
		Status:   domain.ParseStatus(req.Status),
		Profile: domain.UserProfile{
			Nickname: req.Nickname,
			Avatar:   req.Avatar,
			JobTitle: req.JobTitle,
			Phone:    req.Phone,
		},
	}
}

func (u User) ToDomain() domain.User {
	identities := lo.Map(u.Identities, func(src Identity, _ int) domain.UserIdentity {
		return domain.UserIdentity{
			Provider:   src.Provider,
			LdapInfo:   domain.LdapInfo{DN: src.LdapInfo.DN},
			WechatInfo: domain.WechatInfo{UserID: src.WechatInfo.UserID},
			FeishuInfo: domain.FeishuInfo{
				OpenID:  src.FeishuInfo.OpenID,
				UnionID: src.FeishuInfo.UnionID,
				UserID:  src.FeishuInfo.UserID,
			},
		}
	})

	return domain.User{
		ID:          u.ID,
		Username:    u.Username,
		Email:       u.Email,
		Ctime:       u.Ctime,
		Utime:       u.Utime,
		LastLoginAt: u.LastLoginAt,
		Profile: domain.UserProfile{
			Nickname: u.Nickname,
			Avatar:   u.Avatar,
			JobTitle: u.JobTitle,
			Phone:    u.Phone,
		},
		Identities: identities,
		Status:     domain.ParseStatus(u.Status),
	}
}
