package cache

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/Duke1616/eiam/internal/domain"
	"github.com/RediSearch/redisearch-go/v2/redisearch"
	"github.com/gotomicro/ego/core/elog"
)

const (
	LdapUserIndexName = "idx:ldap:users:v2"
	LdapUserKeyPrefix = "eiam:user:ldap:"
	BatchSize         = 500
	PagingSize        = 1000
)

type RedisearchLdapUserCache interface {
	Document(ctx context.Context, tid int64, users []domain.User) error
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
			Set("updated_at", syncTime)

		allDocs = append(allDocs, doc)
	}

	// 1. 并发分批执行索引更新，显著提升大数据量下的同步速度
	g, ctx := errgroup.WithContext(ctx)
	for i := 0; i < len(allDocs); i += BatchSize {
		i := i
		end := i + BatchSize
		if end > len(allDocs) {
			end = len(allDocs)
		}

		g.Go(func() error {
			if err := cache.conn.IndexOptions(redisearch.IndexingOptions{
				Replace: true,
			}, allDocs[i:end]...); err != nil {
				return fmt.Errorf("分批索引写入失败 [%d:%d]: %w", i, end, err)
			}
			return nil
		})
	}

	if err := g.Wait(); err != nil {
		return err
	}

	// 2. 清理过期数据：利用时间戳定位并删除该租户下未参与本次同步的旧数据
	return cache.dropDocument(tid, syncTime)
}

func (cache *redisearchLdapUserCache) dropDocument(tid int64, syncTime int64) error {
	// 构造查询：找出该租户下，更新时间早于本次同步时间的所有文档
	// 语法说明：-@updated_at:[syncTime syncTime] 代表排除当前时间戳
	raw := fmt.Sprintf("@tid:%d -@updated_at:[%d %d]", tid, syncTime, syncTime)

	// 分页查找并删除
	for {
		// 仅返回 ID 即可，降低网络开销
		query := redisearch.NewQuery(raw).SetReturnFields().Limit(0, PagingSize)
		docs, total, err := cache.conn.Search(query)
		if err != nil {
			return err
		}

		if len(docs) == 0 || total == 0 {
			break
		}

		docIds := make([]string, 0, len(docs))
		for _, doc := range docs {
			docIds = append(docIds, doc.Id)
		}

		// 执行并发删除
		g := new(errgroup.Group)
		for _, id := range docIds {
			id := id
			g.Go(func() error {
				return cache.conn.DeleteDocument(id)
			})
		}

		if err := g.Wait(); err != nil {
			return err
		}

		// 如果处理完一批后，剩余总数没有变化，说明可能陷入死循环，应安全退出
		if total <= len(docs) {
			break
		}
	}

	return nil
}

func (cache *redisearchLdapUserCache) next(tid int64, offset, limit int) ([]redisearch.Document, int, error) {
	query := redisearch.NewQuery(fmt.Sprintf("@tid:%d", tid)).
		SetReturnFields(). // 仅返回 ID
		Limit(offset, limit)

	return cache.conn.Search(query)
}

func (cache *redisearchLdapUserCache) Query(ctx context.Context, tid int64, keywords string,
	offset, limit int) ([]domain.User, int, error) {
	defer func() {
		if r := recover(); r != nil {
			cache.logger.Error("LDAP 搜索发生恐慌恢复", elog.Any("recover", r))
		}
	}()

	raw := fmt.Sprintf("@tid:%d", tid)
	if keywords != "" {
		raw = fmt.Sprintf("@tid:%d %s*", tid, keywords)
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

func (cache *redisearchLdapUserCache) key(tid int64, username string) string {
	return fmt.Sprintf("%s%d:%s", LdapUserKeyPrefix, tid, username)
}
