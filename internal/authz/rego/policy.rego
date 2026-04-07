package iam.authz

import rego.v1

default allow := false

# 核心逻辑：任意一个语句允许且没有语句拒绝，则最终允许
# 核心逻辑：候选动作集中存在被允许的动作，且没有任何一个动作被显式拒绝
allow if {
	some statement in input.policies[_].Statement
	statement.Effect == "Allow"
	some action in input.actions
	action_matches(statement.Action, action)
	resource_matches(statement.Resource, input.resource)
	not deny
}

# 显式拒绝规则：只要候选动作集中的任一动作命中 Deny 语句，判定为拒绝
deny if {
	some statement in input.policies[_].Statement
	statement.Effect == "Deny"
	some action in input.actions
	action_matches(statement.Action, action)
	resource_matches(statement.Resource, input.resource)
}

# 辅助规则：Action 匹配（支持通配符，如 iam:*）
action_matches(actions, target_action) if {
	some action in actions
	action == "*"
}

action_matches(actions, target_action) if {
	some action in actions
	action != "*"
	# 显式处理包含通配符的字符串，如果 target_action 也是通配符，则直接通过
	glob.match(action, [":"], target_action)
}

# 辅助规则：Resource 匹配（支持通配符）
resource_matches(resources, target_resource) if {
	some resource in resources
	# 如果是 "*" 则匹配所有
	resource == "*"
}

resource_matches(resources, target_resource) if {
	some resource in resources
	resource != "*"
	# 将 ":" 包装成数组 [":"]
	glob.match(resource, [":"], target_resource)
}
