package logx

// 结构化日志封装，基于标准库 log/slog
// 分通道：access（访问日志）/attack（攻击日志）/system（系统日志）
// 全局统一初始化，避免业务代码各处自建 logger

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
)

// Level 日志级别类型
type Level = slog.Level

const (
	LevelDebug = slog.LevelDebug
	LevelInfo  = slog.LevelInfo
	LevelWarn  = slog.LevelWarn
	LevelError = slog.LevelError
)

var (
	// systemLogger 系统日志（运行状态、错误、启动信息）
	systemLogger *slog.Logger
	// accessLogger 访问日志（对应 jyj_access_log，也写文件）
	accessLogger *slog.Logger
	// attackLogger 攻击日志（对应 jyj_attack_log，也写文件）
	attackLogger *slog.Logger

	once sync.Once
)

// Config 日志初始化配置
type Config struct {
	Level      string
	Dir        string
	MaxSizeMB  int
	MaxBackups int
	MaxAgeDays int
}

// Init 全局日志初始化（仅一次）
func Init(cfg Config) error {
	var initErr error
	once = sync.Once{}
	once.Do(func() {
		// 确保日志目录存在
		if err := os.MkdirAll(cfg.Dir, 0o755); err != nil {
			initErr = fmt.Errorf("创建日志目录失败: %w", err)
			return
		}

		level := parseLevel(cfg.Level)

		// 系统日志：stdout + 文件
		sysFile, err := openLogFile(cfg.Dir, "system.log")
		if err != nil {
			initErr = err
			return
		}
		systemLogger = slog.New(slog.NewJSONHandler(io.MultiWriter(os.Stdout, sysFile), &slog.HandlerOptions{Level: level}))

		// 访问日志文件
		accessFile, err := openLogFile(cfg.Dir, "access.log")
		if err != nil {
			initErr = err
			return
		}
		accessLogger = slog.New(slog.NewJSONHandler(accessFile, &slog.HandlerOptions{Level: level})).With("channel", "access")

		// 攻击日志文件
		attackFile, err := openLogFile(cfg.Dir, "attack.log")
		if err != nil {
			initErr = err
			return
		}
		attackLogger = slog.New(slog.NewJSONHandler(attackFile, &slog.HandlerOptions{Level: level})).With("channel", "attack")
	})
	return initErr
}

// openLogFile 打开日志文件（简单实现，不引入 lumberjack 以减少依赖；
// 生产可替换为带轮转的 writer。文件以追加模式打开）
func openLogFile(dir, name string) (*os.File, error) {
	return os.OpenFile(filepath.Join(dir, name), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
}

func parseLevel(s string) slog.Level {
	switch s {
	case "debug":
		return slog.LevelDebug
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

// 系统日志快捷方法
func Debug(msg string, args ...any) { systemLogger.Debug(msg, args...) }
func Info(msg string, args ...any)  { systemLogger.Info(msg, args...) }
func Warn(msg string, args ...any)  { systemLogger.Warn(msg, args...) }
func Error(msg string, args ...any) { systemLogger.Error(msg, args...) }

// Access 记录访问日志
func Access(ctx context.Context, msg string, args ...any) {
	if accessLogger != nil {
		accessLogger.InfoContext(ctx, msg, args...)
	}
}

// Attack 记录攻击日志
func Attack(ctx context.Context, msg string, args ...any) {
	if attackLogger != nil {
		attackLogger.WarnContext(ctx, msg, args...)
	}
}

// Logger 暴露系统 logger（供需要 context 的场景使用）
func Logger() *slog.Logger {
	return systemLogger
}
