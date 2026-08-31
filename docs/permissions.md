# EIAM 全局权限大盘与元数据字典

> 本文档由 `permgen` 基于全仓 AST 静态分析自动生成。请勿手动修改。
>
> 💡 **联动包含机制**：当为角色分配某项操作权限时，系统将**自动附带拥有**其“联动包含”中的权限，无需管理员手动重复勾选（例如：勾选“修改用户”会自动附带拥有“用户详情”权限）。

- **受控业务模块数**: 9
- **受控权限点总数**: 88


## 模块: 部门管理 (`department`)

- **所属服务**: `iam`
- **定义源码**: `internal/web/department/handler.go`

| 操作名称 | 完整权限码 | 作用域 | 归属类型 | 暴露状态 | 联动包含权限 | 宿主源码位置 |
|:---|:---|:---|:---|:---|:---|:---|
| 创建部门 | `iam:department:add` | 租户级 | 本级 | 正常 | - | `internal/web/department/handler.go` 行 29 |
| 分配部门成员 | `iam:department:assign` | 租户级 | 本级 | 正常 | - | `internal/web/department/handler.go` 行 44 |
| 删除部门 | `iam:department:delete` | 租户级 | 本级 | 正常 | - | `internal/web/department/handler.go` 行 35 |
| 修改部门 | `iam:department:edit` | 租户级 | 本级 | 正常 | - | `internal/web/department/handler.go` 行 32 |
| 部门详情 | `iam:department:get` | 租户级 | 本级 | 正常 | - | `internal/web/department/handler.go` 行 41 |
| 部门成员列表 | `iam:department:members` | 租户级 | 本级 | 正常 | - | `internal/web/department/handler.go` 行 50 |
| 移除部门成员 | `iam:department:remove` | 租户级 | 本级 | 正常 | - | `internal/web/department/handler.go` 行 47 |
| 部门树 | `iam:department:view` | 租户级 | 本级 | 正常 | - | `internal/web/department/handler.go` 行 38 |

---


## 模块: 用户分组 (`group`)

- **所属服务**: `iam`
- **定义源码**: `internal/web/group/handler.go`

| 操作名称 | 完整权限码 | 作用域 | 归属类型 | 暴露状态 | 联动包含权限 | 宿主源码位置 |
|:---|:---|:---|:---|:---|:---|:---|
| 创建用户组 | `iam:group:add` | 租户级 | 本级 | 正常 | - | `internal/web/group/handler.go` 行 30 |
| 分配组成员 | `iam:group:assign_members` | 租户级 | 本级 | 正常 | - | `internal/web/group/handler.go` 行 45 |
| 用户组分配角色 | `iam:group:assign_role` | 租户级 | 本级 | 正常 | - | `internal/web/group/handler.go` 行 60 |
| 删除用户组 | `iam:group:delete` | 租户级 | 本级 | 正常 | - | `internal/web/group/handler.go` 行 36 |
| 修改用户组 | `iam:group:edit` | 租户级 | 本级 | 正常 | - | `internal/web/group/handler.go` 行 33 |
| 用户组详情 | `iam:group:get` | 租户级 | 本级 | 正常 | - | `internal/web/group/handler.go` 行 42 |
| 组成员列表 | `iam:group:members` | 租户级 | 本级 | 正常 | - | `internal/web/group/handler.go` 行 51 |
| 移除组成员 | `iam:group:remove_members` | 租户级 | 本级 | 正常 | - | `internal/web/group/handler.go` 行 48 |
| 用户组解绑角色 | `iam:group:remove_role` | 租户级 | 本级 | 正常 | - | `internal/web/group/handler.go` 行 63 |
| 查看用户组角色 | `iam:group:roles` | 租户级 | 本级 | 正常 | - | `internal/web/group/handler.go` 行 66 |
| 用户组列表 | `iam:group:view` | 租户级 | 本级 | 正常 | - | `internal/web/group/handler.go` 行 39 |

---


## 模块: 身份源管理 (`identity_source`)

- **所属服务**: `iam`
- **定义源码**: `internal/web/identity_source/handler.go`

| 操作名称 | 完整权限码 | 作用域 | 归属类型 | 暴露状态 | 联动包含权限 | 宿主源码位置 |
|:---|:---|:---|:---|:---|:---|:---|
| 删除身份源 | `iam:identity_source:delete` | 系统级 | 本级 | 正常 | - | `internal/web/identity_source/handler.go` 行 38 |
| 身份源详情 | `iam:identity_source:detail` | 系统级 | 本级 | 正常 | - | `internal/web/identity_source/handler.go` 行 41 |
| 保存身份源 | `iam:identity_source:save` | 系统级 | 本级 | 正常 | - | `internal/web/identity_source/handler.go` 行 32 |
| 测试身份源连接 | `iam:identity_source:test` | 系统级 | 本级 | 正常 | - | `internal/web/identity_source/handler.go` 行 44 |
| 切换启用状态 | `iam:identity_source:toggle` | 系统级 | 本级 | 正常 | - | `internal/web/identity_source/handler.go` 行 47 |
| 身份源列表 | `iam:identity_source:view` | 系统级 | 本级 | 正常 | - | `internal/web/identity_source/handler.go` 行 35 |

---


## 模块: 成员治理 (`invitation`)

- **所属服务**: `iam`
- **定义源码**: `internal/web/invitation/handler.go`

| 操作名称 | 完整权限码 | 作用域 | 归属类型 | 暴露状态 | 联动包含权限 | 宿主源码位置 |
|:---|:---|:---|:---|:---|:---|:---|
| 创建邀请 | `iam:invitation:add` | 租户级 | 本级 | 正常 | 角色列表 · `iam:role:view` | `internal/web/invitation/handler.go` 行 45 |
| 批量撤回邀请 | `iam:invitation:batch_delete` | 租户级 | 本级 | 正常 | - | `internal/web/invitation/handler.go` 行 55 |
| 撤回邀请 | `iam:invitation:delete` | 租户级 | 本级 | 正常 | - | `internal/web/invitation/handler.go` 行 52 |
| 处理申请 | `iam:invitation:handle_request` | 租户级 | 本级 | 正常 | - | `internal/web/invitation/handler.go` 行 63 |
| 邀请列表 | `iam:invitation:view` | 租户级 | 本级 | 正常 | - | `internal/web/invitation/handler.go` 行 49 |
| 申请列表 | `iam:invitation:view_requests` | 租户级 | 本级 | 正常 | - | `internal/web/invitation/handler.go` 行 60 |

---


## 模块: 权限管理 (`permission`)

- **所属服务**: `iam`
- **定义源码**: `internal/web/permission/handler.go`

| 操作名称 | 完整权限码 | 作用域 | 归属类型 | 暴露状态 | 联动包含权限 | 宿主源码位置 |
|:---|:---|:---|:---|:---|:---|:---|
| 权限资产清单 | `iam:permission:manifest` | 租户级 | 本级 | 正常 | 批量根据 URN 查询菜单详情 · `iam:permission:menus_by_urns` | `internal/web/permission/handler.go` 行 51 |
| 批量根据 URN 查询菜单详情 | `iam:permission:menus_by_urns` | 租户级 | 本级 | 静默 (不暴露) | - | `internal/web/permission/handler.go` 行 67 |
| 搜索授权主体 | `iam:permission:search_subjects` | 租户级 | 本级 | 正常 | - | `internal/web/permission/handler.go` 行 62 |
| 授权治理列表 | `iam:permission:view_authorizations` | 租户级 | 本级 | 正常 | - | `internal/web/permission/handler.go` 行 57 |

---


## 模块: 策略管理 (`policy`)

- **所属服务**: `iam`
- **定义源码**: `internal/web/policy/handler.go`

| 操作名称 | 完整权限码 | 作用域 | 归属类型 | 暴露状态 | 联动包含权限 | 宿主源码位置 |
|:---|:---|:---|:---|:---|:---|:---|
| 创建策略 | `iam:policy:add` | 租户级 | 本级 | 正常 | 权限资产清单 · `iam:permission:manifest` | `internal/web/policy/handler.go` 行 44 |
| 批量绑定策略 | `iam:policy:batch_attach` | 租户级 | 本级 | 正常 | 策略列表 · `iam:policy:view`<br>搜索授权主体 · `iam:permission:search_subjects` | `internal/web/policy/handler.go` 行 66 |
| 批量删除策略 | `iam:policy:batch_delete` | 租户级 | 本级 | 正常 | - | `internal/web/policy/handler.go` 行 78 |
| 批量解绑策略 | `iam:policy:batch_detach` | 租户级 | 本级 | 正常 | - | `internal/web/policy/handler.go` 行 70 |
| 删除策略 | `iam:policy:delete` | 租户级 | 本级 | 正常 | - | `internal/web/policy/handler.go` 行 75 |
| 解绑策略 | `iam:policy:detach` | 租户级 | 本级 | 正常 | - | `internal/web/policy/handler.go` 行 63 |
| 修改策略 | `iam:policy:edit` | 租户级 | 本级 | 正常 | 权限资产清单 · `iam:permission:manifest`<br>策略详情 · `iam:policy:get` | `internal/web/policy/handler.go` 行 48 |
| 策略详情 | `iam:policy:get` | 租户级 | 本级 | 正常 | - | `internal/web/policy/handler.go` 行 58 |
| 策略列表 | `iam:policy:view` | 租户级 | 本级 | 正常 | - | `internal/web/policy/handler.go` 行 54 |

---


## 模块: 角色管理 (`role`)

- **所属服务**: `iam`
- **定义源码**: `internal/web/policy/handler.go`

| 操作名称 | 完整权限码 | 作用域 | 归属类型 | 暴露状态 | 联动包含权限 | 宿主源码位置 |
|:---|:---|:---|:---|:---|:---|:---|
| 创建角色 | `iam:role:add` | 租户级 | 本级 | 正常 | - | `internal/web/role/handler.go` 行 42 |
| 添加父角色 | `iam:role:add_parent` | 租户级 | 本级 | 正常 | 角色列表 · `iam:role:view` | `internal/web/role/handler.go` 行 79 |
| 分析内联策略 | `iam:role:analysis` | 租户级 | 本级 | 正常 | - | `internal/web/role/handler.go` 行 76 |
| 批量分配角色 | `iam:role:batch_assign` | 租户级 | 本级 | 正常 | 角色列表 · `iam:role:view` | `internal/web/role/handler.go` 行 65 |
| 批量删除角色 | `iam:role:batch_delete` | 租户级 | 本级 | 正常 | - | `internal/web/role/handler.go` 行 60 |
| 批量移除角色 | `iam:role:batch_unassign` | 租户级 | 本级 | 正常 | - | `internal/web/role/handler.go` 行 69 |
| 删除角色 | `iam:role:delete` | 租户级 | 本级 | 正常 | - | `internal/web/role/handler.go` 行 57 |
| 修改角色 | `iam:role:edit` | 租户级 | 本级 | 正常 | - | `internal/web/role/handler.go` 行 45 |
| 角色详情 | `iam:role:get` | 租户级 | 本级 | 正常 | - | `internal/web/role/handler.go` 行 53 |
| 移除父角色 | `iam:role:remove_parent` | 租户级 | 本级 | 正常 | - | `internal/web/role/handler.go` 行 83 |
| 移除角色分配 | `iam:role:unassign` | 租户级 | 本级 | 正常 | - | `internal/web/role/handler.go` 行 72 |
| 角色列表 | `iam:role:view` | 租户级 | 本级 | 正常 | - | `internal/web/role/handler.go` 行 50 |
| 查看个人角色 | `iam:role:view_mine` | 租户级 | 本级 | 正常 | - | `internal/web/role/handler.go` 行 91 |
| 获取父角色 | `iam:role:view_parents` | 租户级 | 本级 | 正常 | - | `internal/web/role/handler.go` 行 86 |
| 角色关联用户列表 | `iam:role:view_role_members` | 租户级 | 跨域 (user) | 正常 | - | `internal/web/user/handler.go` 行 138 |
| 查询角色策略 | `iam:role:view_role_policies` | 租户级 | 跨域 (policy) | 正常 | - | `internal/web/policy/handler.go` 行 88 |

---


## 模块: 租户管理 (`tenant`)

- **所属服务**: `iam`
- **定义源码**: `internal/web/tenant/handler.go`

| 操作名称 | 完整权限码 | 作用域 | 归属类型 | 暴露状态 | 联动包含权限 | 宿主源码位置 |
|:---|:---|:---|:---|:---|:---|:---|
| 创建租户空间 | `iam:tenant:add` | 系统级 | 本级 | 正常 | - | `internal/web/tenant/handler.go` 行 60 |
| 分配租户成员 | `iam:tenant:assign` | 租户级 | 本级 | 正常 | - | `internal/web/tenant/handler.go` 行 92 |
| 批量分配租户成员 | `iam:tenant:batch_assign` | 租户级 | 本级 | 正常 | - | `internal/web/tenant/handler.go` 行 100 |
| 批量删除租户 | `iam:tenant:batch_delete` | 系统级 | 本级 | 正常 | - | `internal/web/tenant/handler.go` 行 78 |
| 批量移除租户成员 | `iam:tenant:batch_unassign` | 租户级 | 本级 | 正常 | - | `internal/web/tenant/handler.go` 行 104 |
| 删除租户空间 | `iam:tenant:delete` | 系统级 | 本级 | 正常 | - | `internal/web/tenant/handler.go` 行 75 |
| 修改租户信息 | `iam:tenant:edit` | 系统级 | 本级 | 正常 | - | `internal/web/tenant/handler.go` 行 72 |
| 查看租户详情 | `iam:tenant:get` | 系统级 | 本级 | 正常 | - | `internal/web/tenant/handler.go` 行 81 |
| 切换租户空间 | `iam:tenant:switch` | 租户级 | 本级 | 静默 (不暴露) | - | `internal/web/tenant/handler.go` 行 51 |
| 移除租户成员 | `iam:tenant:unassign` | 租户级 | 本级 | 正常 | - | `internal/web/tenant/handler.go` 行 96 |
| 全量租户列表 | `iam:tenant:view` | 系统级 | 本级 | 正常 | - | `internal/web/tenant/handler.go` 行 65 |
| 批量查询租户 | `iam:tenant:view_by_ids` | 系统级 | 本级 | 静默 (不暴露) | - | `internal/web/tenant/handler.go` 行 68 |
| 查看租户成员 | `iam:tenant:view_members` | 租户级 | 本级 | 正常 | - | `internal/web/tenant/handler.go` 行 86 |
| 查询我的租户列表 | `iam:tenant:view_mine` | 租户级 | 本级 | 静默 (不暴露) | - | `internal/web/tenant/handler.go` 行 44 |
| 查询用户所属租户 | `iam:tenant:view_user_tenants` | 租户级 | 本级 | 正常 | - | `internal/web/tenant/handler.go` 行 110 |

---


## 模块: 用户管理 (`user`)

- **所属服务**: `iam`
- **定义源码**: `internal/web/policy/handler.go`

| 操作名称 | 完整权限码 | 作用域 | 归属类型 | 暴露状态 | 联动包含权限 | 宿主源码位置 |
|:---|:---|:---|:---|:---|:---|:---|
| 创建用户 | `iam:user:add` | 租户级 | 本级 | 正常 | - | `internal/web/user/handler.go` 行 95 |
| 批量删除用户 | `iam:user:batch_delete` | 租户级 | 本级 | 正常 | - | `internal/web/user/handler.go` 行 105 |
| 删除用户 | `iam:user:delete` | 租户级 | 本级 | 正常 | - | `internal/web/user/handler.go` 行 102 |
| 修改用户 | `iam:user:edit` | 租户级 | 本级 | 正常 | 用户详情 · `iam:user:get` | `internal/web/user/handler.go` 行 98 |
| 用户详情 | `iam:user:get` | 租户级 | 本级 | 正常 | - | `internal/web/user/handler.go` 行 113 |
| 刷新 LDAP 缓存 | `iam:user.ldap:refresh` | 租户级 | 子级 (ldap) | 正常 | - | `internal/web/user/handler.go` 行 125 |
| 搜索 LDAP | `iam:user.ldap:search` | 租户级 | 子级 (ldap) | 正常 | - | `internal/web/user/handler.go` 行 119 |
| 同步 LDAP | `iam:user.ldap:sync` | 租户级 | 子级 (ldap) | 正常 | - | `internal/web/user/handler.go` 行 122 |
| 治理外部身份 | `iam:user:manage_identity` | 租户级 | 本级 | 正常 | - | `internal/web/user/handler.go` 行 130 |
| 解绑外部身份 | `iam:user:unbind_identity` | 租户级 | 本级 | 正常 | - | `internal/web/user/handler.go` 行 133 |
| 用户列表 | `iam:user:view` | 租户级 | 本级 | 正常 | - | `internal/web/user/handler.go` 行 110 |
| 查询用户策略 | `iam:user:view_user_policies` | 租户级 | 跨域 (policy) | 正常 | - | `internal/web/policy/handler.go` 行 83 |
| 查询用户角色 | `iam:user:view_user_roles` | 租户级 | 跨域 (role) | 正常 | - | `internal/web/role/handler.go` 行 96 |

---


