package ldapx

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/url"
	"strings"

	"github.com/Duke1616/eiam/internal/service/user" // 引用接口定义
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
	WhenCreatedAttribute string `mapstructure:"when_created_attribute" json:"when_created_attribute,omitempty"`
	UserFilter           string `mapstructure:"user_filter" json:"user_filter,omitempty"`
	SyncUserFilter       string `mapstructure:"sync_user_filter" json:"sync_user_filter,omitempty"`
	SyncExcludeOu        string `mapstructure:"sync_exclude_ou" json:"sync_exclude_ou,omitempty"`
	GroupFilter          string `mapstructure:"group_filter" json:"group_filter"`
	GroupNameAttribute   string `mapstructure:"group_name_attribute" json:"group_name_attribute"`
}

// Connection LDAP 连接抽象接口，便于扩展和测试
type Connection interface {
	Bind(username, password string) error
	Close()
	Search(searchRequest *ldap.SearchRequest) (*ldap.SearchResult, error)
	SearchWithPaging(searchRequest *ldap.SearchRequest, pagingSize uint32) (*ldap.SearchResult, error)
}

type LdapProvider interface {
	user.IdentityProvider
	CheckConnect() error
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

func (p *ldapProvider) Authenticate(ctx context.Context, username, password string) (user.ExternalProfile, error) {
	var profile user.ExternalProfile
	
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
		
		profile = p.toExternalProfile(sr.Entries[0])
		return nil
	})
	
	if err != nil {
		return user.ExternalProfile{}, err
	}

	err = p.execute(profile.ExternalID, password, func(conn Connection) error {
		return nil 
	})
	if err != nil {
		return user.ExternalProfile{}, fmt.Errorf("LDAP 凭证核验失败: %w", err)
	}

	return profile, nil
}

func (p *ldapProvider) toExternalProfile(entry *ldap.Entry) user.ExternalProfile {
	ext := user.ExternalProfile{
		ExternalID: entry.DN,
		Extra:      make(map[string]string),
	}
	
	for _, attr := range entry.Attributes {
		val := ""
		if len(attr.Values) > 0 {
			val = attr.Values[0]
		}
		
		switch attr.Name {
		case p.conf.UsernameAttribute: 
			ext.Username = val
		case p.conf.MailAttribute: 
			ext.Email = val
		case p.conf.DisplayNameAttribute: 
			ext.Nickname = val
		case p.conf.TitleAttribute: 
			ext.JobTitle = val
		default:
			ext.Extra[attr.Name] = val
		}
	}
	return ext
}

func (p *ldapProvider) getRequiredAttributes() []string {
	return []string{"dn",
		p.conf.MailAttribute,
		p.conf.UsernameAttribute,
		p.conf.DisplayNameAttribute,
		p.conf.TitleAttribute,
	}
}

func (p *ldapProvider) execute(userDN, password string, fn func(conn Connection) error) error {
	conn, err := p.connect(userDN, password)
	if err != nil {
		return err
	}
	defer conn.Close()
	return fn(conn)
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
