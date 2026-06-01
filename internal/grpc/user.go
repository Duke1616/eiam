package grpc

import (
	"context"
	"errors"

	userv1 "github.com/Duke1616/eiam/api/proto/gen/eiam/user/v1"
	"github.com/Duke1616/eiam/internal/domain"
	"github.com/Duke1616/eiam/internal/errs"
	usersvc "github.com/Duke1616/eiam/internal/service/user"
	"github.com/ecodeclub/ekit/slice"
	"github.com/gotomicro/ego/core/elog"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"gorm.io/gorm"
)

type UserServer struct {
	userv1.UnimplementedUserServiceServer

	userSvc usersvc.IUserService
}

func NewUserServer(userSvc usersvc.IUserService) userv1.UserServiceServer {
	return &UserServer{userSvc: userSvc}
}

func (u *UserServer) QueryById(ctx context.Context, req *userv1.QueryByIdReq) (*userv1.QueryUserResp, error) {
	userInfo, err := u.userSvc.GetById(ctx, req.Id)
	if err != nil {
		if u.isSystemError(err) {
			return nil, u.toGRPCError(err)
		}
		return &userv1.QueryUserResp{
			ErrorCode:    u.toGRPCErrorCode(err),
			ErrorMessage: err.Error(),
		}, nil
	}
	return &userv1.QueryUserResp{
		User: u.ToRetrieveUsers(userInfo),
	}, nil
}

func (u *UserServer) QueryByUsernames(ctx context.Context, req *userv1.QueryByUsernamesReq) (*userv1.QueryUsersResp, error) {
	userInfos, err := u.userSvc.GetByUsernames(ctx, req.Usernames)
	if err != nil {
		if u.isSystemError(err) {
			return nil, u.toGRPCError(err)
		}
		return &userv1.QueryUsersResp{
			ErrorCode:    u.toGRPCErrorCode(err),
			ErrorMessage: err.Error(),
		}, nil
	}
	return &userv1.QueryUsersResp{
		Users: slice.Map(userInfos, func(idx int, src domain.User) *userv1.User {
			return u.ToRetrieveUsers(src)
		}),
	}, nil
}

func (u *UserServer) QueryByIds(ctx context.Context, req *userv1.QueryByIdsReq) (*userv1.QueryUsersResp, error) {
	userInfos, err := u.userSvc.GetByIDs(ctx, req.Ids)
	if err != nil {
		if u.isSystemError(err) {
			return nil, u.toGRPCError(err)
		}
		return &userv1.QueryUsersResp{
			ErrorCode:    u.toGRPCErrorCode(err),
			ErrorMessage: err.Error(),
		}, nil
	}
	return &userv1.QueryUsersResp{
		Users: slice.Map(userInfos, func(idx int, src domain.User) *userv1.User {
			return u.ToRetrieveUsers(src)
		}),
	}, nil
}

func (u *UserServer) ToRetrieveUsers(src domain.User) *userv1.User {
	user := &userv1.User{
		Id:          src.ID,
		Username:    src.Username,
		DisplayName: src.Profile.Nickname,
		Email:       src.Email,
		Phone:       src.Profile.Phone,
	}

	if lark, ok := src.GetPrimaryIdentity("feishu"); ok {
		user.LarkUserId = lark.IdentityKey()
	}

	if wechat, ok := src.GetPrimaryIdentity("wechat"); ok {
		user.WechatUserId = wechat.IdentityKey()
	}

	return user
}

// isSystemError 判断是否为系统致命错误（数据库错误、未知系统异常等）
func (u *UserServer) isSystemError(err error) bool {
	if err == nil {
		return false
	}
	return errors.Is(err, errs.ErrDatabaseError) ||
		!u.isBusinessError(err)
}

func (u *UserServer) isBusinessError(err error) bool {
	return errors.Is(err, gorm.ErrRecordNotFound)
}

// toGRPCErrorCode 将常规业务错误映射为 protobuf 定义的 ErrorCode
func (u *UserServer) toGRPCErrorCode(err error) userv1.ErrorCode {
	if err == nil {
		return userv1.ErrorCode_ERROR_CODE_UNSPECIFIED
	}

	switch {
	case errors.Is(err, gorm.ErrRecordNotFound):
		return userv1.ErrorCode_USER_NOT_FOUND
	default:
		return userv1.ErrorCode_INVALID_PARAMETER
	}
}

// toGRPCError 将系统内部 of 业务错误或未知错误，映射为规范的 gRPC status error。
func (u *UserServer) toGRPCError(err error) error {
	if err == nil {
		return nil
	}

	if _, ok := status.FromError(err); ok {
		return err
	}

	// 系统错误，记录日志并统一脱敏返回 codes.Internal
	elog.DefaultLogger.Error("gRPC 接口遭遇系统内部未知异常", elog.FieldErr(err))
	return status.Error(codes.Internal, "服务器内部错误")
}
