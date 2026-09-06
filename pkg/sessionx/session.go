package sessionx

import (
	"github.com/ecodeclub/ginx"
	"github.com/ecodeclub/ginx/session"
	"github.com/gin-gonic/gin"
)

// Destroy 统一彻底销毁用户会话
// 优先调用 Provider.Destroy 以联动触发 TokenCarrier.Clear 清除客户端 Cookie/Header 凭证，
// 并在失败时自动兜底清理 Redis 缓存，彻底避免误调 sess.Destroy 导致客户端 Cookie 残留的问题。
func Destroy(ctx *ginx.Context) error {
	if ctx == nil {
		return nil
	}

	if err := session.DefaultProvider().Destroy(ctx); err != nil {
		// 若因 session 已失效导致 Provider.Get 返回错误，尝试兜底销毁底层存储
		if sess, getErr := session.Get(ctx); getErr == nil && sess != nil {
			_ = sess.Destroy(ctx.Context)
		}
		return err
	}
	return nil
}

// DestroyGin 针对标准 *gin.Context 的快捷销毁方法
func DestroyGin(c *gin.Context) error {
	if c == nil {
		return nil
	}
	return Destroy(&ginx.Context{Context: c})
}
