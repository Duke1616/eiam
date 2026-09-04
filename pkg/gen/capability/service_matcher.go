package capability

import (
	"slices"
	"strings"

	"github.com/Duke1616/eiam/assets"
	"gopkg.in/yaml.v3"
)

// servicePrefixRule 扁平化的微服务前缀匹配规则
type servicePrefixRule struct {
	prefix  string
	service string
}

var servicePrefixRules []servicePrefixRule

func init() {
	var list []struct {
		Code    string   `yaml:"code"`
		Aliases []string `yaml:"aliases"`
	}
	if err := yaml.Unmarshal(assets.ServiceYAML, &list); err != nil {
		return
	}

	seen := make(map[string]bool)
	add := func(p, service string) {
		p = strings.ToLower(strings.TrimSpace(p))
		if p != "" && !seen[p] {
			seen[p] = true
			servicePrefixRules = append(servicePrefixRules, servicePrefixRule{prefix: p, service: service})
		}
	}

	register := func(raw, service string) {
		add(raw, service)
		// NOTE: 若不以 e 开头，则自动派生带 e 前缀的生态命名规则 (如 task -> etask)
		if !strings.HasPrefix(raw, "e") {
			add("e"+raw, service)
		}
	}

	for _, item := range list {
		register(item.Code, item.Code)
		for _, alias := range item.Aliases {
			register(alias, item.Code)
		}
	}

	// 按前缀长度降序排序，确保更精准的长前缀优先匹配 (如 etask 优先于 task)
	slices.SortFunc(servicePrefixRules, func(a, b servicePrefixRule) int {
		return len(b.prefix) - len(a.prefix)
	})
}

// matchService 根据 Go 包名标识符（如 etaskperm / eflowperm）智能推导目标微服务 Code
func matchService(pkg string) string {
	pkg = strings.ToLower(pkg)
	for _, rule := range servicePrefixRules {
		// NOTE: 防御性边界匹配，要求完全相等或紧随规范后缀 (如 perm / permission / _ / -)，
		// 避免意外误伤相同前缀的非服务包名 (如误伤 invitation / document 等)
		if pkg == rule.prefix {
			return rule.service
		}
		if strings.HasPrefix(pkg, rule.prefix) {
			rest := pkg[len(rule.prefix):]
			if strings.HasPrefix(rest, "perm") ||
				strings.HasPrefix(rest, "permission") ||
				strings.HasPrefix(rest, "_") ||
				strings.HasPrefix(rest, "-") {
				return rule.service
			}
		}
	}
	return ""
}
