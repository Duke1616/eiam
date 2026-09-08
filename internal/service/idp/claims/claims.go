package claims

import (
	"strconv"

	"github.com/Duke1616/eiam/internal/domain"
	"github.com/crewjam/saml"
)

// Claims 统一身份声明模型 (规范化收敛 OIDC、CAS、SAML 协议的通用属性定义)
type Claims struct {
	Subject  string   `json:"sub"`
	UserID   int64    `json:"user_id"`
	Username string   `json:"username"`
	Name     string   `json:"name"`
	Nickname string   `json:"nickname,omitempty"`
	Email    string   `json:"email"`
	Phone    string   `json:"phone,omitempty"`
	JobTitle string   `json:"title,omitempty"`
	TenantID int64    `json:"tenant_id"`
	Roles    []string `json:"roles,omitempty"`
}

// FromUser 从基础领域用户实体构造标准化 Claims (纯内存转换，零外部 IO / DB 强耦合)
func FromUser(user domain.User, tenantID int64, roles []string) Claims {
	nickname := user.Profile.Nickname
	name := nickname
	if name == "" {
		name = user.Username
	}

	return Claims{
		Subject:  strconv.FormatInt(user.ID, 10),
		UserID:   user.ID,
		Username: user.Username,
		Name:     name,
		Nickname: nickname,
		Email:    user.Email,
		Phone:    user.Profile.Phone,
		JobTitle: user.Profile.JobTitle,
		TenantID: tenantID,
		Roles:    roles,
	}
}

// ToUser 还原为领域模型 User 实体 (方便各协议回退或统一构造响应)
func (c Claims) ToUser() domain.User {
	return domain.User{
		ID:       c.UserID,
		Username: c.Username,
		Email:    c.Email,
		Profile: domain.UserProfile{
			Nickname: c.Nickname,
			Phone:    c.Phone,
			JobTitle: c.JobTitle,
		},
	}
}

// ToCasAttributes 输出 CAS 2.0 / 3.0 标准属性字典
// fix bug: 严禁在此输出名为 "id" 的属性，防止破坏下游系统 (如 Django/JumpServer) 的 UUIDField 主键约束
func (c Claims) ToCasAttributes() map[string]any {
	attrs := map[string]any{
		"sub":         c.Subject,
		"uid":         c.UserID,
		"user":        c.Username,
		"username":    c.Username,
		"name":        c.Name,
		"displayName": c.Name,
		"nickname":    c.Name,
		"email":       c.Email,
		"phone":       c.Phone,
		"title":       c.JobTitle,
		"tenant_id":   c.TenantID,
	}

	if len(c.Roles) > 0 {
		attrs["roles"] = c.Roles
	}
	return attrs
}

// ToOidcUserInfo 转换为标准 OpenID Connect UserInfo 响应实体
func (c Claims) ToOidcUserInfo() *domain.OidcUserInfo {
	nickname := c.Nickname
	if nickname == "" {
		nickname = c.Name
	}

	return &domain.OidcUserInfo{
		Subject:           c.Subject,
		PreferredUsername: c.Username,
		Name:              c.Name,
		Nickname:          nickname,
		Email:             c.Email,
		EmailVerified:     c.Email != "",
		PhoneNumber:       c.Phone,
		TenantID:          c.TenantID,
		Roles:             c.Roles,
	}
}

// ToSAMLAttributes 输出符合 SAML 2.0 规范的标准属性列表 (包含 basic 格式与企业常用属性映射)
func (c Claims) ToSAMLAttributes() []saml.Attribute {
	buildAttr := func(name string, values ...string) saml.Attribute {
		attrVals := make([]saml.AttributeValue, 0, len(values))
		for _, v := range values {
			if v != "" {
				attrVals = append(attrVals, saml.AttributeValue{
					Type:  "xs:string",
					Value: v,
				})
			}
		}
		return saml.Attribute{
			Name:       name,
			NameFormat: "urn:oasis:names:tc:SAML:2.0:attrname-format:basic",
			Values:     attrVals,
		}
	}

	attrs := []saml.Attribute{
		buildAttr("uid", strconv.FormatInt(c.UserID, 10)),
		buildAttr("username", c.Username),
		buildAttr("name", c.Name),
		buildAttr("displayName", c.Name),
		buildAttr("email", c.Email),
		buildAttr("tenant_id", strconv.FormatInt(c.TenantID, 10)),
	}

	if c.Phone != "" {
		attrs = append(attrs, buildAttr("phone", c.Phone))
	}
	if c.JobTitle != "" {
		attrs = append(attrs, buildAttr("title", c.JobTitle))
	}
	if len(c.Roles) > 0 {
		attrs = append(attrs, buildAttr("roles", c.Roles...))
	}

	return attrs
}
