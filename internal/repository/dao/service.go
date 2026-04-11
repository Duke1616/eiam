package dao

import (
	"context"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// Service 逻辑服务表 (元数据)
type Service struct {
	Id          int64  `gorm:"type:bigint;primaryKey;autoIncrement;comment:'服务ID'"`
	Code        string `gorm:"type:varchar(64);not null;uniqueIndex:uniq_idx_service_code;comment:'服务唯一码'"`
	Name        string `gorm:"type:varchar(128);not null;comment:'展示名称'"`
	Description string `gorm:"type:text;comment:'服务描述'"`
	Ctime       int64  `gorm:"type:bigint;not null;comment:'创建时间'"`
	Utime       int64  `gorm:"type:bigint;not null;comment:'更新时间'"`
}

type IServiceDAO interface {
	BatchUpsert(ctx context.Context, services []Service) error
	ListAll(ctx context.Context) ([]Service, error)
	GetByCode(ctx context.Context, code string) (Service, error)
}

type ServiceDAO struct {
	db *gorm.DB
}

func NewServiceDAO(db *gorm.DB) IServiceDAO {
	return &ServiceDAO{db: db}
}

func (d *ServiceDAO) BatchUpsert(ctx context.Context, services []Service) error {
	if len(services) == 0 {
		return nil
	}

	now := time.Now().UnixMilli()
	for i := range services {
		services[i].Ctime = now
		services[i].Utime = now
	}

	return d.db.WithContext(ctx).Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "code"}},
		DoUpdates: clause.AssignmentColumns([]string{"name", "description", "utime"}),
	}).Create(&services).Error
}

func (d *ServiceDAO) ListAll(ctx context.Context) ([]Service, error) {
	var res []Service
	err := d.db.WithContext(ctx).Find(&res).Error
	return res, err
}

func (d *ServiceDAO) GetByCode(ctx context.Context, code string) (Service, error) {
	var res Service
	err := d.db.WithContext(ctx).Where("code = ?", code).First(&res).Error
	return res, err
}
