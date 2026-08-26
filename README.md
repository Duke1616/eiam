# EIAM

EIAM 是一个统一身份与访问管理平台，提供用户、租户、部门、用户组、角色、策略、权限资产、身份源、邀请等能力。项目同时暴露 HTTP API 和 gRPC 服务，并在启动时完成数据库表结构初始化、SQL 迁移和内置权限资产同步。

## 功能特性

- 多租户身份管理：租户创建、成员分配、租户切换与租户隔离。
- 用户生命周期：用户注册、系统登录、LDAP 登录、密码修改、用户资料、外部身份绑定治理。
- 认证增强：OIDC 登录、Passkey/WebAuthn、TOTP MFA。
- 组织管理：部门树、部门成员、用户组、用户组角色。
- 权限治理：角色、策略、授权关系、菜单权限、API 权限资产发现。
- PBAC 数据范围：OPA 选择策略，Condition 约束授权上下文，AccessScope 描述业务数据范围。
- 身份源管理：标准 OIDC、飞书 OIDC、LDAP 用户搜索与同步。
- 服务接口：Gin HTTP API、gRPC User/Tenant/Department 服务。
- 数据迁移：支持从旧 MongoDB 数据源迁移部门、用户、身份和成员关系。

## 技术栈

- Go 1.25+
- Gin / ego
- GORM / MySQL
- Redis / RediSearch
- Etcd
- Casbin / OPA
- Goose SQL migration
- Cobra / Viper
- Wire
- Protocol Buffers / gRPC

## 目录结构

```text
.
├── api/proto              # gRPC proto 定义
├── cmd                    # Cobra 子命令：server、migrate
├── config                 # 本地配置文件
├── deploy                 # Docker 构建文件
├── internal
│   ├── authz              # OPA 策略
│   ├── domain             # 领域模型
│   ├── grpc               # gRPC service 实现
│   ├── repository         # DAO、Repo、Cache
│   ├── service            # 业务服务
│   ├── test               # 集成测试与测试注入
│   └── web                # HTTP Handler 和 VO
├── ioc                    # Wire 注入与基础设施初始化
├── migrations             # 启动时执行的内嵌 SQL 迁移
└── pkg                    # 可复用工具包
```

## 环境依赖

启动服务前需要准备以下组件：

- MySQL：业务数据、Casbin 策略存储。
- Redis：Session、缓存、RediSearch 索引、Casbin watcher。
- Etcd：服务注册与能力发现。
- 可选 LDAP / OIDC：用于外部身份源登录、搜索和同步。
- 可选 MongoDB：仅在执行旧系统数据迁移时需要。

> `config/config.yaml` 中包含开发环境示例连接信息。实际运行前请复制或替换为自己的本地配置，不要直接复用示例中的地址和密钥。

## 配置说明

默认配置文件路径为 `config/config.yaml`，也可以通过 `--config` 指定：

```bash
go run main.go --config ./config/config.yaml server
```

常用配置项：

```yaml
log:
  debug: true

web:
  host: "0.0.0.0"
  port: 9000

grpc:
  server:
    eiam:
      name: "eiam"
      listen_addr: "0.0.0.0:8077"
      auth_token: "change-me"

mysql:
  dsn: "user:password@tcp(127.0.0.1:3306)/eiam?charset=utf8mb4&parseTime=True&loc=Local&multiStatements=true"

redis:
  addr: "127.0.0.1:6379"
  password: ""
  db: 0

etcd:
  endpoints:
    - 127.0.0.1:2379

session:
  session_encrypted_key: "change-me"
  # 可选值：cookie（默认）或 token。token 模式使用 Authorization: Bearer。
  token_carrier: "cookie"
  cookie:
    domain: "localhost"
    name: "eiam-token"
    secure: true

casbin:
  redis:
    addr: "127.0.0.1:6379"
    db: 2
    password: ""
```

注意事项：

- `mysql.dsn` 必须开启 `parseTime=True`，项目会在启动时执行 `AutoMigrate` 和 `migrations/` 下的 Goose SQL 迁移。
- `session.session_encrypted_key` 不能为空；`cookie` 载体下 `session.cookie.name`、`session.cookie.domain` 也不能为空。
- `session.token_carrier` 默认是 `cookie`；配置为 `token` 时不依赖 Cookie，前端使用 `X-Access-Token` 返回的 Bearer Token。
- `session.cookie.secure` 默认值为 `true`；生产环境应保持开启并使用 HTTPS。
- 本地 HTTP 调试可显式配置 `session.cookie.secure: false`，仅适用于不涉及敏感数据的开发环境。
- gRPC 服务默认读取 `grpc.server.eiam`，并使用 `auth_token` 做 JWT 鉴权配置。

## 本地启动

安装依赖：

```bash
go mod download
```

使用 Task 启动：

```bash
task run
```

或直接启动：

```bash
EGO_DEBUG=true go run main.go server
```

启动成功后：

- HTTP 服务监听 `web.host:web.port`，示例配置为 `0.0.0.0:9000`。
- gRPC 服务监听 `grpc.server.eiam.listen_addr`，示例配置为 `0.0.0.0:8077`。
- 服务会自动建表、执行 SQL 迁移、同步 EIAM 自身 API 权限资产，并启动后台发现任务。

## 常用命令

```bash
# 查看 Taskfile 中的命令
task

# 启动服务
task run

# 生成 proto 代码
task gen

# 生成 mock
task mock

# 运行全部测试
go test ./...
```

PBAC 的 `Action`、`Resource`、`Condition`、`AccessScope` 职责和工单策略示例见 [PBAC Condition 与 AccessScope](docs/pbac-data-filter.md)。

## 数据迁移

项目里有两类迁移，需要区分使用：

1. 应用启动迁移：服务启动时自动执行 `dao.InitTables` 和 `migrations/` 下的 Goose SQL 脚本。
2. 旧系统数据迁移：通过 `migrate` 子命令从旧 MongoDB 数据源迁移部门、用户、身份、成员关系等数据。

执行旧系统数据迁移：

```bash
go run main.go --config ./config/config.yaml migrate
```

强制重新执行迁移步骤：

```bash
go run main.go --config ./config/config.yaml migrate --force
```

迁移相关配置位于 `migration`：

```yaml
migration:
  source:
    mongo:
      dsn: "mongodb://user:password@127.0.0.1:27017/source_db?authSource=admin"
  identity:
    version: "V1"
    key: "change-me"
  batch_size: 100
  timeout: "10m"
  auto_migrate: true
  truncate: false
  dry_run: false
```

## API 模块

HTTP 路由主要按以下模块组织：

- `/api/user`：注册、登录、用户管理、LDAP、OIDC、Passkey、MFA。
- `/api/tenant`：租户列表、租户切换、租户成员治理。
- `/api/department`：部门树、部门详情、部门成员。
- `/api/group`：用户组、组成员、组角色。
- `/api/role`：角色、角色继承、角色授权。
- `/api/policy`：策略创建、绑定、解绑和查询。
- `/api/permission`：登录检查、菜单、权限资产、授权治理。
- `/api/identity_source`：身份源保存、测试、启停、查询。
- `/api/invitation`：邀请验证、接受、撤回、申请处理。
- `/api/v1/discovery`：权限资产同步。

gRPC proto 定义位于 `api/proto/eiam`，当前包含：

- `user/v1`
- `tenant/v1`
- `department/v1`

## Docker

构建镜像：

```bash
docker build -f deploy/Dockerfile -t eiam:local .
```

运行镜像时需要挂载或注入配置文件，并确保容器可以访问 MySQL、Redis 和 Etcd：

```bash
docker run --rm \
  -v "$PWD/config/config.yaml:/app/config/config.yaml" \
  -p 9000:9000 \
  -p 8077:8077 \
  eiam:local
```

## 开发说明

- 新增 HTTP 能力时，优先在对应 `internal/web/<module>/handler.go` 中声明路由，并使用 `Capability` 描述权限资产。
- 新增业务表时，更新 `internal/repository/dao` 并确认 `dao.InitTables` 覆盖该实体。
- 需要固定初始化数据时，优先新增 `migrations/` 下的 Goose SQL 脚本。
- 修改 proto 后执行 `task gen` 重新生成代码。
- 集成测试配置位于 `internal/test/config/config.yaml`，运行前请确认测试 MySQL/Redis 指向隔离环境。
