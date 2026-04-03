-- +goose Up
-- +goose StatementBegin
-- 录入两大核心角色：SUPER_ADMIN（全局超级管理员）、ADMIN（租户管理员）
-- 注意：tenant_id = 0 代表全租户空间的系统预设角色模板。
INSERT INTO `role` (`tenant_id`, `code`, `name`, `type`, `policies`, `ctime`, `utime`) VALUES 
(0, 'SUPER_ADMIN', '系统全局超级管理员', 1, 
 '[{"Name":"ROOT全量授权","Type":1,"Statement":[{"Effect":"Allow","Action":["*"],"Resource":["*"]}]}]', 
 UNIX_TIMESTAMP(NOW(3))*1000, UNIX_TIMESTAMP(NOW(3))*1000),

(0, 'ADMIN', '租户管理员', 1, 
 '[{"Name":"敏感权限熔断策略","Type":1,"Statement":[{"Effect":"Deny","Action":["iam:tenant:*","iam:permission:global:*"],"Resource":["*"]}]}]', 
 UNIX_TIMESTAMP(NOW(3))*1000, UNIX_TIMESTAMP(NOW(3))*1000)
ON DUPLICATE KEY UPDATE `name`=VALUES(`name`), `policies`=VALUES(`policies`), `utime`=VALUES(`utime`);

-- 建立继承关系：租户管理员继承全局全量能力，但受到其自身 Deny 策略的约束
INSERT INTO `casbin_rule` (`ptype`, `v0`, `v1`, `v2`) VALUES 
('g', 'ADMIN', 'SUPER_ADMIN', '0')
ON DUPLICATE KEY UPDATE `v2`=VALUES(`v2`);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DELETE FROM `role` WHERE `tenant_id` = 0 AND `code` IN ('SUPER_ADMIN', 'ADMIN');
DELETE FROM `casbin_rule` WHERE `ptype` = 'g' AND `v0` = 'ADMIN' AND `v1` = 'SUPER_ADMIN';
-- +goose StatementEnd
