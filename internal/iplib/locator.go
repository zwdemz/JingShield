package iplib

// IP 归属地查询接口
// 抽象出归属地查询能力，便于切换不同 IP 库实现（QQWry / 在线 API 等）

// Locator IP 归属地查询器
type Locator interface {
	// Lookup 查询 IP 归属地，返回中文地址字符串；查询失败返回空串
	Lookup(ip string) string
	// Available 数据文件是否可用
	Available() bool
}
