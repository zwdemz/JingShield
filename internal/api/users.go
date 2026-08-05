package api

import (
	"errors"
	"net/http"
	"net/mail"
	"regexp"
	"strconv"
	"strings"

	"jingshield/internal/model"
	"jingshield/internal/repository"

	"github.com/go-sql-driver/mysql"
)

var adminUsernamePattern = regexp.MustCompile(`^[A-Za-z0-9_.-]{3,50}$`)

func (a *API) userList(w http.ResponseWriter, r *http.Request) {
	users, err := a.users.List(r.Context())
	if err != nil {
		a.internalError(w, r, err)
		return
	}
	if users == nil {
		users = []*model.User{}
	}
	writeOK(w, "success", users)
}

func (a *API) userCreate(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Username string `json:"username"`
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := decodeJSON(w, r, &in); err != nil {
		writeError(w, http.StatusBadRequest, -3, "请求参数格式错误")
		return
	}
	in.Username = strings.TrimSpace(in.Username)
	in.Email = strings.TrimSpace(in.Email)
	if !adminUsernamePattern.MatchString(in.Username) || len(in.Password) < 12 || len(in.Password) > 255 || len(in.Email) > 100 || !validOptionalEmail(in.Email) {
		writeError(w, http.StatusBadRequest, -3, "用户名须为 3-50 位字母、数字或 ._-，密码须为 12-255 字符，邮箱格式须有效")
		return
	}
	hash, err := repository.HashPassword(in.Password)
	if err != nil {
		a.internalError(w, r, err)
		return
	}
	user, err := a.users.Create(r.Context(), in.Username, in.Email, hash)
	if err != nil {
		var mysqlErr *mysql.MySQLError
		if errors.As(err, &mysqlErr) && mysqlErr.Number == 1062 {
			writeError(w, http.StatusConflict, -3, "用户名已经存在")
			return
		}
		a.internalError(w, r, err)
		return
	}
	writeOK(w, "管理员已创建，首次登录必须修改密码", user)
}

func (a *API) userStatusPut(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	var in struct {
		Enabled bool `json:"enabled"`
	}
	if err != nil || id <= 0 || decodeJSON(w, r, &in) != nil {
		writeError(w, http.StatusBadRequest, -3, "用户状态参数非法")
		return
	}
	current := currentSession(r)
	if id == current.UserID && !in.Enabled {
		writeError(w, http.StatusConflict, -3, "不能停用当前登录账号")
		return
	}
	status := 0
	if in.Enabled {
		status = 1
	}
	if err := a.users.SetStatus(r.Context(), id, status); err != nil {
		switch {
		case errors.Is(err, repository.ErrUserNotFound):
			writeError(w, http.StatusNotFound, -404, err.Error())
		case errors.Is(err, repository.ErrLastActiveUser):
			writeError(w, http.StatusConflict, -3, err.Error())
		default:
			a.internalError(w, r, err)
		}
		return
	}
	if !in.Enabled {
		a.sessions.deleteUser(id)
	}
	writeOK(w, "用户状态已更新", nil)
}

func (a *API) userPasswordReset(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	var in struct {
		NewPassword string `json:"new_password"`
	}
	if err != nil || id <= 0 || decodeJSON(w, r, &in) != nil || len(in.NewPassword) < 12 || len(in.NewPassword) > 255 {
		writeError(w, http.StatusBadRequest, -3, "临时密码须为 12-255 字符")
		return
	}
	if id == currentSession(r).UserID {
		writeError(w, http.StatusConflict, -3, "当前账号请使用个人改密功能")
		return
	}
	hash, err := repository.HashPassword(in.NewPassword)
	if err != nil {
		a.internalError(w, r, err)
		return
	}
	if err := a.users.ResetPassword(r.Context(), id, hash); err != nil {
		if errors.Is(err, repository.ErrUserNotFound) {
			writeError(w, http.StatusNotFound, -404, err.Error())
		} else {
			a.internalError(w, r, err)
		}
		return
	}
	a.sessions.deleteUser(id)
	writeOK(w, "临时密码已重置，目标用户下次登录必须修改密码", nil)
}

func validOptionalEmail(value string) bool {
	if value == "" {
		return true
	}
	address, err := mail.ParseAddress(value)
	return err == nil && address.Address == value
}
