package certx

import (
	"errors"
	"fmt"
	"os"
	"strings"
)

// Source 约束可作为证书或密钥数据源的合法输入类型
type Source interface {
	~string | ~[]byte
}

// ResolveSource 智能探测并解析证书/密钥数据源
// 识别策略：
// 1. 若内容包含 "-----BEGIN"，判定为直接内联的 PEM 字符串，直接返回字节；
// 2. 若内容不含换行符且长度符合文件路径规范，判定为本地磁盘文件路径；若文件不存在或读取失败，明确返回文件读取错误；
// 3. 兜底返回原始字节切片 (兼容原始 DER 二进制编码)。
func ResolveSource[T Source](input T) ([]byte, error) {
	bytes := []byte(input)
	trimmed := strings.TrimSpace(string(bytes))
	if trimmed == "" {
		return nil, errors.New("证书或密钥数据源内容不能为空")
	}

	// 1. 优先匹配内联 PEM 字符串，规避将其当作文件路径进行多余的磁盘 I/O
	if strings.Contains(trimmed, "-----BEGIN") {
		return []byte(trimmed), nil
	}

	// 2. 单行且不含换行符，明确判定为本地文件路径
	if !strings.Contains(trimmed, "\n") && len(trimmed) < 4096 {
		content, err := os.ReadFile(trimmed)
		if err != nil {
			return nil, fmt.Errorf("读取证书/密钥文件失败 (%s): %w", trimmed, err)
		}
		return content, nil
	}

	// 3. 多行原始字节兜底 (如纯 DER 二进制编码)
	return bytes, nil
}
