-- +goose Up
-- +goose StatementBegin
-- 录入两大核心角色：super_admin (全局超级管理员)、admin (租户管理员)
-- 注意：tenant_id = 0 代表全租户空间的系统预置角色模板。
INSERT INTO `role` (`tenant_id`, `code`, `name`, `type`, `inline_policies`, `ctime`, `utime`)
VALUES (0, 'super_admin', '系统全局超级管理员', 1,
        '[{"Name":"ROOT全量授权","Type":1,"Statement":[{"Effect":"Allow","Action":["*"],"Resource":["*"]}]}]',
        (UNIX_TIMESTAMP(NOW(3)) * 1000), (UNIX_TIMESTAMP(NOW(3)) * 1000)),
       (0, 'admin', '租户管理员', 1,
        '[{"Name":"敏感权限熔断策略","Type":1,"Statement":[{"Effect":"Deny","Action":["iam:tenant:*","iam:permission:global:*"],"Resource":["*"]}]}]',
        (UNIX_TIMESTAMP(NOW(3)) * 1000), (UNIX_TIMESTAMP(NOW(3)) * 1000))
ON DUPLICATE KEY UPDATE `name`            = VALUES(`name`),
                        `inline_policies` = VALUES(`inline_policies`),
                        `utime`           = VALUES(`utime`);

-- 建立继承关系：租户管理员继承全局超管能力，但受到其自身策略约束
-- Casbin 规范：v0(子角色) v1(父角色) v2(域)
-- 使用 INSERT INTO ... ON DUPLICATE KEY 确保幂等
INSERT INTO `casbin_rule` (`ptype`, `v0`, `v1`, `v2`)
VALUES ('g', 'role:admin', 'role:super_admin', '0')
ON DUPLICATE KEY UPDATE `v2` = VALUES(`v2`);

-- 初始化超级管理员账户：admin / 12345678
INSERT INTO `user` (`id`, `username`, `password`, `email`, `status`, `ctime`, `utime`)
VALUES (1, 'admin', '$2a$10$6ocvB6VX93BKFT4HruyWEOFy1ePGbXbd37uBvtnZ7CHovY9N3WotK', 'admin@example.com', 1,
        (UNIX_TIMESTAMP(NOW(3)) * 1000), (UNIX_TIMESTAMP(NOW(3)) * 1000))
ON DUPLICATE KEY UPDATE `password` = VALUES(`password`), `utime` = VALUES(`utime`);

-- 授予 admin 用户 super_admin 角色 (使用 username: admin)
INSERT INTO `casbin_rule` (`ptype`, `v0`, `v1`, `v2`)
VALUES ('g', 'user:admin', 'role:super_admin', '0')
ON DUPLICATE KEY UPDATE `v2` = VALUES(`v2`);

-- 初始化 admin 用户的个人租户空间
INSERT INTO `tenant` (`id`, `name`, `code`, `domain`, `status`, `ctime`, `utime`)
VALUES (1, '系统管理员的个人空间', 'admin-personal', 'localhost', 1,
        (UNIX_TIMESTAMP(NOW(3)) * 1000), (UNIX_TIMESTAMP(NOW(3)) * 1000))
ON DUPLICATE KEY UPDATE `name` = VALUES(`name`), `code` = VALUES(`code`), `utime` = VALUES(`utime`);


-- 初始化 admin 用户的租户成员关联（Membership）
INSERT INTO `membership` (`id`, `tenant_id`, `user_id`, `ctime`)
VALUES (1, 1, 1, (UNIX_TIMESTAMP(NOW(3)) * 1000))
ON DUPLICATE KEY UPDATE `ctime` = VALUES(`ctime`);

-- 初始化 admin 用户的个人名片（UserProfile）
INSERT INTO `user_profile` (`id`, `membership_id`, `nickname`, `avatar`, `job_title`)
VALUES (1, 1, '系统管理员', '', 'CEO')
ON DUPLICATE KEY UPDATE `nickname` = VALUES(`nickname`);


-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DELETE FROM `role` WHERE `tenant_id` = 0 AND `code` IN ('super_admin', 'admin');
DELETE FROM `casbin_rule` WHERE `ptype` = 'g' AND `v0` = 'role:admin' AND `v1` = 'role:super_admin' AND `v2` = '0';
DELETE FROM `user` WHERE `username` = 'admin';
DELETE FROM `casbin_rule` WHERE `ptype` = 'g' AND `v0` = 'user:admin' AND `v1` = 'role:super_admin' AND `v2` = '0';
DELETE FROM `tenant` WHERE `code` = 'admin-personal';

DELETE FROM `membership` WHERE `user_id` = 1 AND `tenant_id` = 1;
DELETE FROM `user_profile` WHERE `membership_id` = 1;


-- +goose StatementEnd
