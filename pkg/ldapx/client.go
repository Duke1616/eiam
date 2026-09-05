package ldapx

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/go-ldap/ldap/v3"
)

// Config 通用 LDAP 客户端配置
type Config struct {
	URL                string `mapstructure:"url" json:"url,omitempty"`
	BaseDN             string `mapstructure:"base_dn" json:"base_dn,omitempty"`
	BindDN             string `mapstructure:"bind_dn" json:"bind_dn,omitempty"`
	BindPassword       string `mapstructure:"bind_password" json:"bind_password,omitempty"`
	InsecureSkipVerify bool   `mapstructure:"insecure_skip_verify" json:"insecure_skip_verify,omitempty"`
}

// IClient 通用 LDAP 客户端接口
type IClient interface {
	// CheckConnect 测试与 LDAP 服务器的连通性及管理员绑定鉴权
	CheckConnect() error

	// Authenticate 核验用户身份，基于指定过滤条件检索用户条目并尝试以用户 DN 绑定核验密码
	Authenticate(ctx context.Context, userFilter, password string, attributes []string) (*ldap.Entry, error)

	// SearchWithPaging 使用分页机制执行 LDAP 检索并返回所有匹配条目
	SearchWithPaging(ctx context.Context, filter string, attributes []string, pageSize uint32) ([]*ldap.Entry, error)

	// Search 执行底层自定义 LDAP 搜索请求
	Search(req *ldap.SearchRequest) (*ldap.SearchResult, error)
}

type client struct {
	cfg Config
}

// NewClient 构建通用 LDAP 客户端
func NewClient(cfg Config) IClient {
	return &client{cfg: cfg}
}

func (c *client) CheckConnect() error {
	conn, err := c.connect(c.cfg.BindDN, c.cfg.BindPassword)
	if err != nil {
		return err
	}
	conn.Close()
	return nil
}

func (c *client) Authenticate(ctx context.Context, userFilter, password string, attributes []string) (*ldap.Entry, error) {
	if password == "" {
		return nil, errors.New("用户密码不能为空")
	}

	adminConn, err := c.connect(c.cfg.BindDN, c.cfg.BindPassword)
	if err != nil {
		return nil, err
	}
	defer adminConn.Close()

	if len(attributes) == 0 {
		attributes = []string{"*"}
	}
	searchReq := ldap.NewSearchRequest(
		c.cfg.BaseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
		1, 0, false, userFilter, attributes, nil,
	)

	sr, err := adminConn.Search(searchReq)
	if err != nil || len(sr.Entries) == 0 {
		return nil, fmt.Errorf("LDAP 用户不存在: %w", err)
	}
	userEntry := sr.Entries[0]

	userConn, err := c.connect(userEntry.DN, password)
	if err != nil {
		return nil, fmt.Errorf("LDAP 凭据核验失败: %w", err)
	}
	userConn.Close()

	return userEntry, nil
}

func (c *client) SearchWithPaging(ctx context.Context, filter string, attributes []string, pageSize uint32) ([]*ldap.Entry, error) {
	conn, err := c.connect(c.cfg.BindDN, c.cfg.BindPassword)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	if filter == "" {
		filter = "(objectClass=*)"
	}
	if pageSize == 0 {
		pageSize = 500
	}

	searchReq := ldap.NewSearchRequest(
		c.cfg.BaseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
		0, 0, false, filter, attributes, nil,
	)

	sr, err := conn.SearchWithPaging(searchReq, pageSize)
	if err != nil {
		return nil, fmt.Errorf("LDAP 分页搜索失败: %w", err)
	}
	return sr.Entries, nil
}

func (c *client) Search(req *ldap.SearchRequest) (*ldap.SearchResult, error) {
	conn, err := c.connect(c.cfg.BindDN, c.cfg.BindPassword)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	return conn.Search(req)
}

func (c *client) connect(bindDN, password string) (*ldap.Conn, error) {
	u, err := url.Parse(c.cfg.URL)
	if err != nil {
		return nil, fmt.Errorf("解析 LDAP URL 失败: %w", err)
	}

	var conn *ldap.Conn
	if u.Scheme == "ldaps" {
		conn, err = ldap.DialURL(c.cfg.URL, ldap.DialWithTLSConfig(&tls.Config{InsecureSkipVerify: c.cfg.InsecureSkipVerify}))
	} else {
		conn, err = ldap.DialURL(c.cfg.URL)
	}
	if err != nil {
		return nil, fmt.Errorf("建立 LDAP 连接失败: %w", err)
	}

	if err = conn.Bind(bindDN, password); err != nil {
		conn.Close()
		return nil, fmt.Errorf("LDAP Bind 认证失败 (%s): %w", bindDN, err)
	}
	return conn, nil
}

// ResolveUserFilter 替换过滤器占位符并转义用户输入
func ResolveUserFilter(filter, username, usernameAttr, mailAttr string) string {
	escaped := ldap.EscapeFilter(username)
	replacer := strings.NewReplacer(
		"{input}", escaped,
		"{username_attribute}", usernameAttr,
		"{mail_attribute}", mailAttr,
	)
	return replacer.Replace(filter)
}
