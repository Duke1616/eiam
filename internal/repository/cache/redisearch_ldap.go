package cache

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/Duke1616/eiam/internal/domain"
	"github.com/RediSearch/redisearch-go/v2/redisearch"
	"github.com/gotomicro/ego/core/elog"
)

const (
	LdapUserIndexName = "idx:ldap:users:v3"
	LdapUserKeyPrefix = "eiam:user:ldap:"
	BatchSize         = 500
	PagingSize        = 1000
	MaxDropIterations = 50 // 防御性退出阈值，防止数据清理发生死循环
)

// NewLdapUserSchema 统一维护 LDAP 用户 RediSearch 索引元数据结构
// 供 ioc 初始化与后续可能发生的索引重建调用
func NewLdapUserSchema() *redisearch.Schema {
	return redisearch.NewSchema(redisearch.DefaultOptions).
		AddField(redisearch.NewTagField("tid")). // TagField 用于租户 ID 的高效率、精确匹配
		AddField(redisearch.NewTextField("username")).
		AddField(redisearch.NewTextField("display_name")).
		AddField(redisearch.NewTextField("title")).
		AddField(redisearch.NewTextField("email")).
		AddField(redisearch.NewTextField("phone")).
		AddField(redisearch.NewTextField("dn")).
		AddField(redisearch.NewNumericField("updated_at"))
}

// RedisearchLdapUserCache 基于 RediSearch 的 LDAP 用户搜索缓存
// 提供高性能的关键词模糊搜索和分页查询能力
type RedisearchLdapUserCache interface {
	// Document 将 LDAP 用户数据批量同步到 RediSearch 索引中
	Document(ctx context.Context, tid int64, users []domain.User) error
	// Query 执行基于关键词的 LDAP 用户搜索
	Query(ctx context.Context, tid int64, keywords string, offset, limit int) ([]domain.User, int, error)
}

type redisearchLdapUserCache struct {
	conn   *redisearch.Client
	logger *elog.Component
}

func NewRedisearchLdapUserCache(conn *redisearch.Client) RedisearchLdapUserCache {
	return &redisearchLdapUserCache{
		conn:   conn,
		logger: elog.DefaultLogger,
	}
}

func (cache *redisearchLdapUserCache) Document(ctx context.Context, tid int64, users []domain.User) error {
	allDocs := make([]redisearch.Document, 0, len(users))
	syncTime := time.Now().UnixMilli()

	for _, user := range users {
		docKey := cache.key(tid, user.Username)
		doc := redisearch.NewDocument(docKey, 1.0)
		doc.Set("tid", strconv.FormatInt(tid, 10)).
			Set("username", user.Username).
			Set("display_name", user.Profile.Nickname).
			Set("title", user.Profile.JobTitle).
			Set("email", user.Email).
			Set("phone", user.Profile.Phone).
			Set("updated_at", syncTime)

		if ident, ok := user.GetPrimaryIdentity(domain.LDAP.String()); ok {
			doc.Set("dn", ident.LdapInfo.DN)
		}

		allDocs = append(allDocs, doc)
	}

	// 1. 并发分批执行索引更新，显著提升大数据量下的同步速度
	g, gCtx := errgroup.WithContext(ctx)
	// 限制并发 batch 数量，避免瞬间耗尽 Redis 客户端连接池
	g.SetLimit(10)

	for i := 0; i < len(allDocs); i += BatchSize {
		start := i
		end := start + BatchSize
		if end > len(allDocs) {
			end = len(allDocs)
		}

		batch := allDocs[start:end]
		g.Go(func() error {
			select {
			case <-gCtx.Done():
				return gCtx.Err()
			default:
			}
			if err := cache.conn.IndexOptions(redisearch.IndexingOptions{
				Replace: true,
			}, batch...); err != nil {
				return fmt.Errorf("分批索引写入失败 [%d:%d]: %w", start, end, err)
			}
			return nil
		})
	}

	if err := g.Wait(); err != nil {
		return err
	}

	// 2. 清理过期数据：利用时间戳定位并删除该租户下未参与本次同步的旧数据
	return cache.dropDocument(ctx, tid, syncTime)
}

func (cache *redisearchLdapUserCache) dropDocument(ctx context.Context, tid int64, syncTime int64) error {
	// 构造查询：找出该租户下更新时间早于本次同步时间的旧文档
	// Tag 字段匹配语法为 @tid:{%d}，排除当前时间戳语法为 -@updated_at:[syncTime syncTime]
	raw := fmt.Sprintf("@tid:{%d} -@updated_at:[%d %d]", tid, syncTime, syncTime)

	for iteration := 0; iteration < MaxDropIterations; iteration++ {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		// 仅返回 ID 降低网络负载
		query := redisearch.NewQuery(raw).SetReturnFields().Limit(0, PagingSize)
		docs, _, err := cache.conn.Search(query)
		if err != nil {
			return fmt.Errorf("查找待删除旧数据失败: %w", err)
		}

		if len(docs) == 0 {
			break
		}

		// 批量并发删除，限制并发协程数防打满连接池
		g, gCtx := errgroup.WithContext(ctx)
		g.SetLimit(10)

		for _, doc := range docs {
			id := doc.Id
			g.Go(func() error {
				select {
				case <-gCtx.Done():
					return gCtx.Err()
				default:
				}
				return cache.conn.DeleteDocument(id)
			})
		}

		if err := g.Wait(); err != nil {
			return fmt.Errorf("批量删除过期 LDAP 文档失败: %w", err)
		}

		// 如果本批取出的数量已少于 PagingSize，说明已是最后一批数据
		if len(docs) < PagingSize {
			break
		}
	}

	return nil
}

func (cache *redisearchLdapUserCache) Query(ctx context.Context, tid int64, keywords string,
	offset, limit int) ([]domain.User, int, error) {
	defer func() {
		if r := recover(); r != nil {
			cache.logger.Error("LDAP 搜索发生恐慌恢复", elog.Any("recover", r))
		}
	}()

	var raw string
	cleanKeywords := escapeQueryString(strings.TrimSpace(keywords))
	if cleanKeywords != "" {
		// 模糊前缀匹配，严格限定在对应租户范围内
		raw = fmt.Sprintf("@tid:{%d} %s*", tid, cleanKeywords)
	} else {
		raw = fmt.Sprintf("@tid:{%d}", tid)
	}

	query := redisearch.NewQuery(raw).
		Limit(offset, limit).
		SetReturnFields("username", "display_name", "title", "email", "phone", "dn")

	docs, total, err := cache.conn.Search(query)
	if err != nil {
		return nil, 0, err
	}

	users := make([]domain.User, 0, len(docs))
	for _, doc := range docs {
		u := domain.User{
			Username: getPropString(doc.Properties, "username"),
			Email:    getPropString(doc.Properties, "email"),
			Profile: domain.UserProfile{
				Nickname: getPropString(doc.Properties, "display_name"),
				JobTitle: getPropString(doc.Properties, "title"),
				Phone:    getPropString(doc.Properties, "phone"),
			},
		}

		if dn := getPropString(doc.Properties, "dn"); dn != "" {
			u.Identities = []domain.UserIdentity{
				{
					Provider:   domain.LDAP.String(),
					IdentityID: dn,
					LdapInfo:   domain.LdapInfo{DN: dn},
				},
			}
		}

		users = append(users, u)
	}

	return users, total, nil
}

func (cache *redisearchLdapUserCache) key(tid int64, username string) string {
	return fmt.Sprintf("%s%d:%s", LdapUserKeyPrefix, tid, username)
}

func getPropString(props map[string]any, key string) string {
	if v, ok := props[key]; ok && v != nil {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

// escapeQueryString 对用户输入的 RediSearch 保留符号进行转义或清洗
// 避免因输入特殊字符（如 @, :, -, /, ., *, (, ) 等）导致 RediSearch 查询语法解析失败
func escapeQueryString(s string) string {
	if s == "" {
		return ""
	}

	// RediSearch 查询语法中的保留字符
	specialChars := []string{
		"\\", ",", ".", "<", ">", "{", "}", "[", "]",
		"\"", "'", ":", ";", "!", "@", "#", "$", "%",
		"^", "&", "*", "(", ")", "-", "+", "=", "~",
		"|", "/", "?",
	}

	var replacerArgs []string
	for _, char := range specialChars {
		replacerArgs = append(replacerArgs, char, "\\"+char)
	}

	r := strings.NewReplacer(replacerArgs...)
	return r.Replace(s)
}

