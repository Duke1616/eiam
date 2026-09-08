-- +goose Up
-- 1. 兼容保障：若历史表 oauth_clients 不存在（全新用户），创建临时空表；若已存在（老用户），安全跳过保留原数据
CREATE TABLE IF NOT EXISTS `oauth_clients` (
    `id` BIGINT AUTO_INCREMENT PRIMARY KEY,
    `tenant_id` BIGINT NOT NULL DEFAULT 0,
    `client_id` VARCHAR(64) NOT NULL DEFAULT '',
    `client_secret_hash` VARCHAR(255) NOT NULL DEFAULT '',
    `name` VARCHAR(128) NOT NULL DEFAULT '',
    `logo` VARCHAR(255) DEFAULT '',
    `redirect_uris` JSON,
    `response_types` JSON,
    `grant_types` JSON,
    `scopes` JSON,
    `is_public` TINYINT(1) NOT NULL DEFAULT 0,
    `auto_consent` TINYINT(1) NOT NULL DEFAULT 1,
    `ctime` BIGINT,
    `utime` BIGINT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 2. 确保 application 表结构建立（包含最新的 protocol 协议字段与索引）
CREATE TABLE IF NOT EXISTS `application` (
    `id` BIGINT AUTO_INCREMENT PRIMARY KEY,
    `tenant_id` BIGINT NOT NULL COMMENT '归属租户ID (0表示全局)',
    `protocol` VARCHAR(32) NOT NULL DEFAULT 'oidc' COMMENT '接入协议类型: oidc, cas, saml',
    `client_id` VARCHAR(64) NOT NULL UNIQUE COMMENT '应用唯一客户端标识',
    `client_secret_hash` VARCHAR(255) NOT NULL DEFAULT '' COMMENT '客户端密钥哈希',
    `name` VARCHAR(128) NOT NULL COMMENT '应用名称',
    `logo` VARCHAR(255) DEFAULT '' COMMENT '应用图标URL',
    `redirect_uris` JSON COMMENT '合法重定向白名单',
    `response_types` JSON COMMENT '允许的响应类型',
    `grant_types` JSON COMMENT '允许的授权模式',
    `scopes` JSON COMMENT '允许申请的权限范围',
    `is_public` TINYINT(1) NOT NULL DEFAULT 0 COMMENT '是否为公共客户端',
    `auto_consent` TINYINT(1) NOT NULL DEFAULT 1 COMMENT '是否跳过授权确认',
    `ctime` BIGINT COMMENT '创建时间戳',
    `utime` BIGINT COMMENT '更新时间戳',
    INDEX `idx_application_tenant_id` (`tenant_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='统一接入应用表';

-- 3. 将 oauth_clients 历史数据无损导入新表 application（全新用户此处复制 0 条，老用户自动平滑迁移且补齐 protocol='oidc'）
INSERT IGNORE INTO `application` (
    `id`, `tenant_id`, `protocol`, `client_id`, `client_secret_hash`,
    `name`, `logo`, `redirect_uris`, `response_types`, `grant_types`,
    `scopes`, `is_public`, `auto_consent`, `ctime`, `utime`
)
SELECT 
    `id`, `tenant_id`, 'oidc', `client_id`, `client_secret_hash`,
    `name`, `logo`, `redirect_uris`, `response_types`, `grant_types`,
    `scopes`, `is_public`, `auto_consent`, `ctime`, `utime`
FROM `oauth_clients`;

-- 4. 彻底清理已完成历史使命的旧表
DROP TABLE IF EXISTS `oauth_clients`;

-- 5. 存量记录兜底修正：确保所有历史未指定协议的应用均规范补齐为 'oidc'
UPDATE `application` SET `protocol` = 'oidc' WHERE `protocol` IS NULL OR `protocol` = '';

-- +goose Down
-- 降级保护：保留 application 表
