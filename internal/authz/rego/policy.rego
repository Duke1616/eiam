package iam.authz

import rego.v1

default allow := false

# --- 1. 单一资源判定逻辑 (用于 CheckAPI/CheckPermission) ---

allow if {
	some action in input.actions
	is_allowed(action, resource_scoped_statements)
	not has_deny_action(input.actions, resource_scoped_statements)
}

# --- 2. 批量资源判定逻辑 (用于 GetAuthorizedMenus 等场景) ---

# 一次性返回 batch_resources 中所有允许访问的资源 URN 集合
allowed_resources contains res if {
	some res in input.batch_resources
	# 为每个资源动态筛选生效的 Statements
	statements := [stmt | 
		some policy in input.policies
		some stmt in policy.Statement
		match_pattern(stmt.Resource, res)
	]
	
	# 从映射表获取该资源对应的动作候选人集 (如该菜单关联的所有 Permission Code)
	actions := input.resource_actions[res]
	some action in actions
	is_allowed(action, statements)
	not has_deny_action(actions, statements)
}

# --- 3. 准入与拒绝谓词 (抽离以复用) ---

is_allowed(action, statements) if {
	some statement in statements
	statement.Effect == "Allow"
	match_pattern(statement.Action, action)
}

has_deny_action(target_actions, statements) if {
	some statement in statements
	statement.Effect == "Deny"
	some action in target_actions
	match_pattern(statement.Action, action)
}

# --- 4. 辅助：单一资源作用域预过滤 ---
resource_scoped_statements contains statement if {
	some policy in input.policies
	some statement in policy.Statement
	match_pattern(statement.Resource, input.resource)
}

# --- 5. 通用逻辑匹配工具 ---
match_pattern(patterns, target) if {
	"*" in patterns
}

match_pattern(patterns, target) if {
	some pattern in patterns
	pattern != "*"
	glob.match(pattern, [":"], target)
}
