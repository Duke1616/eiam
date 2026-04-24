package ldapx

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/url"
	"strings"

	"github.com/Duke1616/eiam/internal/domain"
	"github.com/go-ldap/ldap/v3"
)

// Config LDAP 配置定义
type Config struct {
	Url                  string `mapstructure:"url" json:"url,omitempty"`
	BaseDN               string `mapstructure:"base_dn" json:"base_dn,omitempty"`
	BindDN               string `mapstructure:"bind_dn" json:"bind_dn,omitempty"`
	BindPassword         string `mapstructure:"bind_password" json:"bind_password,omitempty"`
	UsernameAttribute    string `mapstructure:"username_attribute" json:"username_attribute,omitempty"`
	MailAttribute        string `mapstructure:"mail_attribute" json:"mail_attribute,omitempty"`
	DisplayNameAttribute string `mapstructure:"display_name_attribute" json:"display_name_attribute,omitempty"`
	TitleAttribute       string `mapstructure:"title_attribute" json:"title_attribute,omitempty"`
	PhoneAttribute       string `mapstructure:"phone_attribute" json:"phone_attribute,omitempty"`
	UserFilter           string `mapstructure:"user_filter" json:"user_filter,omitempty"`
	SyncUserFilter       string `mapstructure:"sync_user_filter" json:"sync_user_filter,omitempty"`
}

// Connection LDAP 连接抽象
type Connection interface {
	Bind(username, password string) error
	Close()
	Search(searchRequest *ldap.SearchRequest) (*ldap.SearchResult, error)
	SearchWithPaging(searchRequest *ldap.SearchRequest, pagingSize uint32) (*ldap.SearchResult, error)
}

type LdapProvider interface {
	domain.IdentityProvider
	CheckConnect() error
	SearchUserWithPaging(ctx context.Context) ([]domain.User, error)
}

type ldapProvider struct {
	conf Config
}

func NewLdap(conf Config) LdapProvider {
	return &ldapProvider{conf: conf}
}

func (p *ldapProvider) Name() string {
	return "ldap"
}

// SearchUserWithPaging 全量分页搜索用户
func (p *ldapProvider) SearchUserWithPaging(ctx context.Context) ([]domain.User, error) {
	var users []domain.User
	err := p.execute(p.conf.BindDN, p.conf.BindPassword, func(conn Connection) error {
		filter := p.conf.SyncUserFilter
		if filter == "" {
			filter = p.conf.UserFilter
		}
		// 容错处理：如果没有配置 filter，默认搜索所有人员
		if filter == "" {
			filter = "(objectClass=*)"
		}

		searchRequest := ldap.NewSearchRequest(
			p.conf.BaseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
			0, 0, false, filter, p.getRequiredAttributes(), nil,
		)

		// 默认每页 500 条
		sr, innerErr := conn.SearchWithPaging(searchRequest, 500)
		if innerErr != nil {
			return fmt.Errorf("LDAP 分页搜索失败: %w", innerErr)
		}

		for _, entry := range sr.Entries {
			users = append(users, p.buildDraftUser(entry))
		}
		return nil
	})

	return users, err
}

// Authenticate 适配：支持契约化侧写构造
func (p *ldapProvider) Authenticate(ctx context.Context, username, password string) (domain.User, error) {
	var userInfo domain.User
	// 1. 查找资料阶段
	err := p.execute(p.conf.BindDN, p.conf.BindPassword, func(conn Connection) error {
		filter := p.resolveUserFilter(p.conf.UserFilter, username)
		searchRequest := ldap.NewSearchRequest(
			p.conf.BaseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
			1, 0, false, filter, p.getRequiredAttributes(), nil,
		)
		sr, innerErr := conn.Search(searchRequest)
		if innerErr != nil || len(sr.Entries) == 0 {
			return fmt.Errorf("LDAP 用户不存在: %s", username)
		}

		// 构建领域 User 雏形
		userInfo = p.buildDraftUser(sr.Entries[0])
		return nil
	})

	if err != nil {
		return domain.User{}, err
	}

	// 2. 校验凭证阶段
	// 此时仅核验账号本身的有效性。具体的 Membership 关联将在 Service 层决据
	id, _ := userInfo.GetPrimaryIdentity("ldap")
	err = p.execute(id.IdentityKey(), password, func(conn Connection) error {
		return nil
	})
	if err != nil {
		return domain.User{}, fmt.Errorf("LDAP 凭证核验失败: %w", err)
	}

	return userInfo, nil
}

// buildDraftUser 构造一个带有所需属性但尚未绑定 MembershipID 的 User 雏形
func (p *ldapProvider) buildDraftUser(entry *ldap.Entry) domain.User {
	u := domain.User{
		Status:  domain.StatusActive,
		Profile: domain.UserProfile{},
		Identities: []domain.UserIdentity{
			{
				Provider: "ldap",
				LdapInfo: domain.LdapInfo{DN: entry.DN},
			},
		},
	}

	for _, attr := range entry.Attributes {
		val := ""
		if len(attr.Values) > 0 {
			val = attr.Values[0]
		}

		name := attr.Name
		if strings.EqualFold(name, p.conf.UsernameAttribute) {
			u.Username = val
		} else if strings.EqualFold(name, p.conf.MailAttribute) {
			u.Email = val
		} else if strings.EqualFold(name, p.conf.DisplayNameAttribute) {
			u.Profile.Nickname = val
		} else if strings.EqualFold(name, p.conf.TitleAttribute) {
			u.Profile.JobTitle = val
		} else if strings.EqualFold(name, p.conf.PhoneAttribute) {
			u.Profile.Phone = val
		}
	}
	return u
}

func (p *ldapProvider) getRequiredAttributes() []string {
	return []string{"dn",
		p.conf.MailAttribute,
		p.conf.UsernameAttribute,
		p.conf.DisplayNameAttribute,
		p.conf.TitleAttribute,
		p.conf.PhoneAttribute,
	}
}

func (p *ldapProvider) execute(userDN, password string, funcBody func(conn Connection) error) error {
	conn, err := p.connect(userDN, password)
	if err != nil {
		return err
	}
	defer conn.Close()
	return funcBody(conn)
}

func (p *ldapProvider) connect(userDN string, password string) (Connection, error) {
	u, err := url.Parse(p.conf.Url)
	if err != nil {
		return nil, err
	}

	var conn *ldap.Conn
	if u.Scheme == "ldaps" {
		conn, err = ldap.DialURL(p.conf.Url, ldap.DialWithTLSConfig(&tls.Config{InsecureSkipVerify: true}))
	} else {
		conn, err = ldap.DialURL(p.conf.Url)
	}

	if err != nil {
		return nil, fmt.Errorf("LDAP 连接失败: %w", err)
	}

	if err = conn.Bind(userDN, password); err != nil {
		conn.Close()
		return nil, fmt.Errorf("LDAP 绑定失败 (%s): %w", userDN, err)
	}

	return &ConnectionImpl{conn: conn}, nil
}

func (p *ldapProvider) resolveUserFilter(userFilter string, username string) string {
	username = ldap.EscapeFilter(username)
	replacer := strings.NewReplacer(
		"{input}", username,
		"{username_attribute}", p.conf.UsernameAttribute,
		"{mail_attribute}", p.conf.MailAttribute,
	)
	return replacer.Replace(userFilter)
}

func (p *ldapProvider) CheckConnect() error {
	return p.execute(p.conf.BindDN, p.conf.BindPassword, func(conn Connection) error { return nil })
}

// ConnectionImpl 基础封装
type ConnectionImpl struct {
	conn *ldap.Conn
}

func (lc *ConnectionImpl) Bind(username, password string) error {
	return lc.conn.Bind(username, password)
}

func (lc *ConnectionImpl) Close() {
	lc.conn.Close()
}

func (lc *ConnectionImpl) Search(req *ldap.SearchRequest) (*ldap.SearchResult, error) {
	return lc.conn.Search(req)
}

func (lc *ConnectionImpl) SearchWithPaging(req *ldap.SearchRequest, size uint32) (*ldap.SearchResult, error) {
	return lc.conn.SearchWithPaging(req, size)
}
