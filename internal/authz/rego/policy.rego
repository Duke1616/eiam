package iam.authz

import rego.v1

default allow := false

# --- 核心判定逻辑 ---

# 判定原则：
# 1. 输入的 Actions 中，必须至少有一个动作被“允许” (Match Allow)
# 2. 输入的 Actions 中，没有任何一个动作被“显式拒绝” (Match Deny)
allow if {
	some action in input.actions
	is_allowed(action)
	not has_deny_action
}

# --- 准入谓词 ---

# 检查特定动作为什么被允许
is_allowed(action) if {
	some statement in resource_scoped_statements
	statement.Effect == "Allow"
	match_pattern(statement.Action, action)
}

# 检查是否存在任何被拒绝的动作
# 一次性判定，只要 input.actions 中任一动作命中 Deny 语句，则整个请求熔断
has_deny_action if {
	some statement in resource_scoped_statements
	statement.Effect == "Deny"
	some action in input.actions
	match_pattern(statement.Action, action)
}

# --- 预处理：资源作用域过滤 ---

# 性能优化核心：预先筛选出匹配当前 URN 的所有语句，避免在 allow/deny 判定中重复计算资源匹配
resource_scoped_statements contains statement if {
	some policy in input.policies
	some statement in policy.Statement
	match_pattern(statement.Resource, input.resource)
}

# --- 通用匹配工具 ---

# 支持通配符 "*" 全量匹配
match_pattern(patterns, target) if {
	"*" in patterns
}

# 支持 Glob 模式匹配（如 "iam:user:*"）
match_pattern(patterns, target) if {
	some pattern in patterns
	pattern != "*"
	# 利用 glob.match 处理分段匹配，[":"] 为分隔符，对 URN 友好
	glob.match(pattern, [":"], target)
}
