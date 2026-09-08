package claims

import (
	"testing"

	"github.com/Duke1616/eiam/internal/domain"
	"github.com/stretchr/testify/assert"
)

func TestFromUser(t *testing.T) {
	t.Run("有昵称时优先使用昵称", func(t *testing.T) {
		user := domain.User{
			ID:       1001,
			Username: "alice",
			Email:    "alice@example.com",
			Profile: domain.UserProfile{
				Nickname: "爱丽丝",
				Phone:    "13800000000",
				JobTitle: "安全工程师",
			},
		}

		c := FromUser(user, 1, []string{"admin", "editor"})
		assert.Equal(t, "1001", c.Subject)
		assert.Equal(t, "alice", c.Username)
		assert.Equal(t, "爱丽丝", c.Name)
		assert.Equal(t, "爱丽丝", c.Nickname)

		// 验证 CAS 属性
		casAttrs := c.ToCasAttributes()
		assert.Equal(t, int64(1001), casAttrs["uid"])
		assert.Equal(t, "alice", casAttrs["user"])
		assert.Equal(t, "爱丽丝", casAttrs["name"])
		assert.Equal(t, "alice@example.com", casAttrs["email"])
		assert.Nil(t, casAttrs["id"], "严禁包含 id 字段，避免破坏下游 UUIDField")

		// 验证 OIDC UserInfo
		userInfo := c.ToOidcUserInfo()
		assert.Equal(t, "1001", userInfo.Subject)
		assert.Equal(t, "alice", userInfo.PreferredUsername)
		assert.Equal(t, "爱丽丝", userInfo.Name)
		assert.Equal(t, "爱丽丝", userInfo.Nickname)
		assert.Equal(t, []string{"admin", "editor"}, userInfo.Roles)
	})

	t.Run("昵称为空时自动回退为用户名", func(t *testing.T) {
		user := domain.User{
			ID:       1002,
			Username: "bob",
		}

		c := FromUser(user, 1, nil)
		assert.Equal(t, "bob", c.Name)
		assert.Equal(t, "", c.Nickname)
		casAttrs := c.ToCasAttributes()
		assert.Equal(t, "bob", casAttrs["name"])
	})

	t.Run("验证 ToUser 转换", func(t *testing.T) {
		c := Claims{
			UserID:   2001,
			Username: "david",
			Nickname: "大卫",
			Email:    "david@example.com",
			Phone:    "13900000000",
			JobTitle: "架构师",
			TenantID: 1,
		}

		user := c.ToUser()
		assert.Equal(t, int64(2001), user.ID)
		assert.Equal(t, "david", user.Username)
		assert.Equal(t, "大卫", user.Profile.Nickname)
		assert.Equal(t, "david@example.com", user.Email)
		assert.Equal(t, "13900000000", user.Profile.Phone)
		assert.Equal(t, "架构师", user.Profile.JobTitle)
	})
}
