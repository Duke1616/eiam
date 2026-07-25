# PBAC Condition 与 AccessScope

## 职责边界

EIAM 的 PBAC 授权链保留 OPA 作为策略选择引擎：

```text
OPA 匹配 Action 与 API Resource
    -> EIAM 完整求值 Condition
    -> EIAM 解析并返回业务 AccessScope
    -> SDK 校验 API 声明的 FilterProfile
    -> 业务服务将 AccessScope 编译为参数化查询
```

- `Action` 表示允许执行的能力，例如 `ticket:manager:history`。
- `Resource` 表示这条 Statement 作用于哪个授权目标。当前接口鉴权使用 API URN，也可以用 `*`；它不表示数据库中的某一行工单。
- `Condition` 表示授权成立的上下文约束，只允许主体、认证、请求和环境等 EIAM 可立即求值的属性。
- `AccessScope` 表示授权后的业务数据范围，例如 `ticket:create_by`、`ticket:related_users` 和 `task:assignee`，由 EIAM 解析可信属性引用后交给业务服务求值。
- `FilterProfile` 是 API 与业务查询之间的固定编译契约。它由服务端能力声明并随 API 资产持久化，调用方不能在鉴权请求中自行指定。

FilterProfile 名称应显式包含版本，例如 `ticket_history.v1`。业务字段或查询语义发生不兼容变化时发布新版本，避免已登记资产与 SDK 编译逻辑发生静默漂移。

业务 API 通过 capability builder 的 `.AccessScope(profile)` 声明固定 profile；该声明随 API 资产上报，鉴权调用方不能覆盖。

EIAM 不生成业务 SQL，也不理解工单表结构。通用的 GORM AccessScope 编译器位于 `pkg/pbac/gormx`，字段白名单、表名和关联关系由业务服务的 profile 提供。

## 工单策略示例

管理员查看全部历史工单不需要 AccessScope：

```json
{
  "Effect": "Allow",
  "Action": ["ticket:manager:history"],
  "Resource": ["*"]
}
```

普通用户只能查看自己创建或与自己有关的历史工单：

```json
{
  "Effect": "Allow",
  "Action": ["ticket:manager:history"],
  "Resource": ["*"],
  "AccessScope": {
    "any": [
      {
        "predicate": {
          "key": "ticket:create_by",
          "operator": "StringEquals",
          "values": [
            {"type": "ref", "value": "principal:username"}
          ]
        }
      },
      {
        "predicate": {
          "key": "ticket:related_users",
          "operator": "ForAnyValue:StringEquals",
          "values": [
            {"type": "ref", "value": "principal:username"}
          ]
        }
      }
    ]
  }
}
```

普通用户查看全部待办时，可以只允许当前处理人匹配的任务：

```json
{
  "Effect": "Allow",
  "Action": ["ticket:manager:todo"],
  "Resource": ["*"],
  "AccessScope": {
    "predicate": {
      "key": "task:assignee",
      "operator": "StringEquals",
      "values": [
        {"type": "ref", "value": "principal:username"}
      ]
    }
  }
}
```

`StringContains` 表示字符串子串匹配，不用于集合成员关系。AccessScope 的集合成员关系使用 `ForAnyValue:StringEquals`。

Condition 与 AccessScope 不能混用：业务属性写入 Condition、EIAM 属性写入 AccessScope 都会在策略创建或更新时被拒绝。需要表达 OR 条件时，可以使用多条 Statement；AccessScope 内部的 `any` 用于表达同一授权语句下业务行范围的并集。

## 生效条件属性

当前由 EIAM 填充并立即求值的 Condition 属性只有：

- 主体：`principal:username`
- 环境：`environment:current_time`

用户名来自 EIAM 验证后的身份，当前时间由 EIAM 服务端生成。HTTP 方法和路径只用于定位 API 资产及其绑定的 Action，不属于 Condition；租户隔离由系统授权边界负责，也不作为可配置条件。

来源 IP、多因素认证状态和安全传输状态只有在认证会话与服务调用链能够提供可信值后才适合加入。在此之前不声明占位属性，避免策略可以保存却无法在所有鉴权入口得到一致结果。

`principal:`、`environment:`、`request:` 和 `auth:` 是 EIAM 保留命名空间。AccessScope 的业务属性不能使用这些前缀，属性引用只能指向 EIAM 当前明确支持的 Condition 属性。

## 失败策略

- API 声明了 AccessScope profile 但没有绑定 Action：拒绝。
- 策略产生 AccessScope，但 API 没有声明 `FilterProfile`：拒绝。
- EIAM 返回的 profile 与 SDK 本地声明不一致：拒绝。
- 业务 profile 不支持某个 key、operator 或 operand：拒绝，不执行查询。
- 所有值都通过 GORM 参数绑定进入查询，不允许 Condition 提供 SQL 标识符或 SQL 片段。
