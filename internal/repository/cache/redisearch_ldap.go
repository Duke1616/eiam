package cache

import (
	"context"
	"fmt"

	"github.com/Duke1616/eiam/internal/domain"
	"github.com/RediSearch/redisearch-go/v2/redisearch"
	"github.com/gotomicro/ego/core/elog"
	"golang.org/x/sync/errgroup"
)

const (
	KeyPrefix  = "eiam:user:ldap:"
	BatchSize  = 500
	PagingSize = 1000
)

type RedisearchLdapUserCache interface {
	Document(ctx context.Context, users []domain.User) error
	Query(ctx context.Context, keywords string, offset, limit int) ([]domain.User, int, error)
}

type redisearchLdapUserCache struct {
	conn   *redisearch.Client
	logger *elog.Component
}

func NewRedisearchLdapUserCache(conn *redisearch.Client) RedisearchLdapUserCache {
	logger := elog.DefaultLogger
	sc := redisearch.NewSchema(redisearch.DefaultOptions).
		AddField(redisearch.NewTextField("username")).
		AddField(redisearch.NewTextField("display_name")).
		AddField(redisearch.NewTextField("title")).
		AddField(redisearch.NewTextField("email"))

	// 检查索引是否已经存在
	_, err := conn.Info()
	if err != nil {
		indexDefinition := redisearch.NewIndexDefinition().AddPrefix(KeyPrefix)
		if err = conn.CreateIndexWithIndexDefinition(sc, indexDefinition); err != nil {
			logger.Error("redisearch 创建索引失败, 将影响 LDAP 获取用户功能", elog.FieldErr(err))
		}
	}

	return &redisearchLdapUserCache{
		conn:   conn,
		logger: logger,
	}
}

func (cache *redisearchLdapUserCache) Document(ctx context.Context, users []domain.User) error {
	existDocs := make(map[string]bool, len(users))
	allDocs := make([]redisearch.Document, 0, len(users))

	for _, user := range users {
		docKey := cache.key(user.Username)
		doc := redisearch.NewDocument(docKey, 1.0)
		doc.Set("username", user.Username).
			Set("display_name", user.Profile.Nickname).
			Set("title", user.Profile.JobTitle).
			Set("email", user.Email)

		allDocs = append(allDocs, doc)
		existDocs[docKey] = true
	}

	// 1. 分批执行索引更新，避免大数据量下单个请求过大
	for i := 0; i < len(allDocs); i += BatchSize {
		end := i + BatchSize
		if end > len(allDocs) {
			end = len(allDocs)
		}

		if err := cache.conn.IndexOptions(redisearch.IndexingOptions{
			Replace: true,
		}, allDocs[i:end]...); err != nil {
			return fmt.Errorf("分批索引写入失败 [%d:%d]: %w", i, end, err)
		}
	}

	// 2. 清理已经不存在于本次同步列表中的旧数据
	return cache.dropDocument(existDocs)
}

func (cache *redisearchLdapUserCache) dropDocument(existDocs map[string]bool) error {
	// 获取当前索引中所有文档的总数
	_, total, err := cache.next(0, 0)
	if err != nil {
		return err
	}

	// 如果现有数据量与索引总量一致，说明无需清理
	if len(existDocs) >= total {
		return nil
	}

	// 遍历索引找出待删除的 DocID
	var docIds []string
	offset := 0
	for offset < total {
		docs, _, err := cache.next(offset, PagingSize)
		if err != nil {
			return err
		}
		if len(docs) == 0 {
			break
		}

		for _, doc := range docs {
			if !existDocs[doc.Id] {
				docIds = append(docIds, doc.Id)
			}
		}
		offset += PagingSize
	}

	if len(docIds) == 0 {
		return nil
	}

	// 3. 并行删除多余的数据，显著提升清理阶段效率
	g := new(errgroup.Group)
	// 控制并发量，避免瞬间对 Redis 造成过大压力
	sem := make(chan struct{}, 10)
	for _, id := range docIds {
		id := id
		sem <- struct{}{}
		g.Go(func() error {
			defer func() { <-sem }()
			return cache.conn.DeleteDocument(id)
		})
	}

	return g.Wait()
}

func (cache *redisearchLdapUserCache) next(offset, limit int) ([]redisearch.Document, int, error) {
	query := redisearch.NewQuery("*").
		SetReturnFields(). // 仅返回 ID
		Limit(offset, limit)

	return cache.conn.Search(query)
}

func (cache *redisearchLdapUserCache) Query(ctx context.Context, keywords string,
	offset, limit int) ([]domain.User, int, error) {
	defer func() {
		if r := recover(); r != nil {
			cache.logger.Error("LDAP 搜索发生恐慌恢复", elog.Any("recover", r))
		}
	}()

	raw := "*"
	if keywords != "" {
		raw = fmt.Sprintf("*%s*", keywords)
	}

	query := redisearch.NewQuery(raw).
		Limit(offset, limit).
		SetReturnFields("username", "display_name", "title", "email")

	docs, total, err := cache.conn.Search(query)
	if err != nil {
		return nil, 0, err
	}

	users := make([]domain.User, 0, len(docs))
	for _, doc := range docs {
		users = append(users, domain.User{
			Username: doc.Properties["username"].(string),
			Email:    doc.Properties["email"].(string),
			Profile: domain.UserProfile{
				Nickname: doc.Properties["display_name"].(string),
				JobTitle: doc.Properties["title"].(string),
			},
		})
	}

	return users, total, nil
}

func (cache *redisearchLdapUserCache) key(username string) string {
	return KeyPrefix + username
}
