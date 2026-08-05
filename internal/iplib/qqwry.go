package iplib

// 纯真 IP 库（QQWry.Dat）二进制解析实现
// 对应 PHP IP/ip.function.php 的 convertip()
//
// QQWry.Dat 文件格式：
//   文件头 8 字节：前 4 字节=首条记录偏移(begin)，后 4 字节=末条记录偏移(end)，均小端 uint32
//   每条索引记录 7 字节：4 字节起始 IP(小端) + 3 字节指向结束记录的偏移
//   结束记录：4 字节结束 IP + 地区数据（含 1/2 字节重定向标记）
//
// 查询采用二分搜索：按起始 IP 定位区间，再读取地区数据
// 地区数据可能含重定向（flag=1 单重定向，flag=2 双重定向）

import (
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"

	"jingshield/internal/pkg/iputil"

	"golang.org/x/text/encoding/simplifiedchinese"
)

// QQWry 纯真 IP 库查询器
type QQWry struct {
	file *os.File
	mu   sync.Mutex
	// 缓存：IP -> 归属地（对应原 /cache/{md5(ip)}.txt，避免重复二分搜索）
	cache     map[string]string
	cacheMu   sync.RWMutex
	cacheSize int
}

// gbkDecoder GBK -> UTF-8 解码器
var gbkDecoder = simplifiedchinese.GBK.NewDecoder()

// NewQQWry 打开纯真 IP 库文件
func NewQQWry(datPath string) (*QQWry, error) {
	f, err := os.Open(datPath)
	if err != nil {
		return nil, fmt.Errorf("打开 IP 库文件失败: %w", err)
	}
	return &QQWry{
		file:      f,
		cache:     make(map[string]string, 1024),
		cacheSize: 10000, // 缓存上限，超出不再缓存（防内存膨胀）
	}, nil
}

// Available 数据文件是否可用
func (q *QQWry) Available() bool {
	return q.file != nil
}

// Close 关闭文件
func (q *QQWry) Close() error {
	if q.file != nil {
		return q.file.Close()
	}
	return nil
}

// Lookup 查询 IP 归属地
// 对应 PHP convertip()，含内网识别与结果清洗
func (q *QQWry) Lookup(ip string) string {
	if q.file == nil || !iputil.ValidateIP(ip) {
		return ""
	}

	// 内网快速识别（对应 PHP local_ips 判断）
	if iputil.IsPrivateIP(ip) {
		return "局域网"
	}

	// 仅支持 IPv4（QQWry.Dat 为 IPv4 库）
	ipNum, err := iputil.IPToUint32(ip)
	if err != nil {
		return ""
	}

	// 命中缓存直接返回
	if loc := q.getCache(ip); loc != "" {
		return loc
	}

	// 文件读取需加锁（os.File 的 Seek/Read 非并发安全）
	q.mu.Lock()
	defer q.mu.Unlock()

	location := q.search(ip, ipNum)
	// 结果清洗
	location = cleanLocation(ip, location)
	q.setCache(ip, location)
	return location
}

// search 二分搜索定位 IP 区间并读取地区数据
// 对应 PHP convertip() 的 while 二分循环
func (q *QQWry) search(ip string, ipNum uint32) string {
	// 读取文件头 8 字节：begin 与 end 偏移
	header := make([]byte, 8)
	if _, err := q.file.ReadAt(header, 0); err != nil {
		return ""
	}
	begin := binary.LittleEndian.Uint32(header[0:4])
	end := binary.LittleEndian.Uint32(header[4:8])

	// 记录总数
	total := (end - begin) / 7

	lo, hi := uint32(0), total
	var mid, startIP, endIP uint32

	for lo < hi {
		mid = lo + (hi-lo)/2

		// 读取索引记录：4 字节起始 IP + 3 字节结束记录偏移
		off := int64(begin + mid*7)
		rec := make([]byte, 7)
		if _, err := q.file.ReadAt(rec, off); err != nil {
			return ""
		}
		startIP = binary.LittleEndian.Uint32(rec[0:4])
		endOff := readUint24(rec[4:7]) // 结束记录偏移（3 字节）

		if ipNum < startIP {
			hi = mid
			continue
		}

		// 读取结束记录：4 字节结束 IP
		endRec := make([]byte, 4)
		if _, err := q.file.ReadAt(endRec, int64(endOff)); err != nil {
			return ""
		}
		endIP = binary.LittleEndian.Uint32(endRec[0:4])

		if ipNum > endIP {
			lo = mid + 1
			continue
		}

		// 命中区间，读取地区数据（endOff + 4 起）
		return q.readRegion(int64(endOff) + 4)
	}
	return ""
}

// readRegion 读取地区数据，处理重定向标记
// 对应 PHP convertip() 中 ipFlag == chr(1)/chr(2) 的重定向逻辑
func (q *QQWry) readRegion(off int64) string {
	// 读取 1 字节 flag
	flag := make([]byte, 1)
	if _, err := q.file.ReadAt(flag, off); err != nil {
		return ""
	}

	switch flag[0] {
	case 1:
		// 单重定向：读 3 字节偏移，跳转后再次读取地区
		redirectOff := make([]byte, 3)
		q.file.ReadAt(redirectOff, off+1)
		newOff := int64(readUint24(redirectOff))
		return q.readRegion(newOff)
	case 2:
		// 双重定向：先读地区2偏移(3字节)，地区1在当前位置+4处，地区2在偏移处
		redirectOff := make([]byte, 3)
		q.file.ReadAt(redirectOff, off+1)
		addr2Off := int64(readUint24(redirectOff))
		addr2 := q.readCString(addr2Off)
		// 地区1紧跟在 3 字节偏移后
		addr1 := q.readCString(off + 4)
		return joinAddr(addr1, addr2)
	default:
		// 无重定向：地区1从当前位置起（flag 字节已读，回退1字节）
		addr1 := q.readCString(off)
		// 地区2紧跟地区1后，可能有 flag=2 重定向
		addr2Off := off + int64(len(addr1)) + 1 // +1 跳过 null 终止符
		addr2 := q.readAddr2(addr2Off)
		return joinAddr(addr1, addr2)
	}
}

// readAddr2 读取地区2，可能含 flag=2 重定向
func (q *QQWry) readAddr2(off int64) string {
	flag := make([]byte, 1)
	if _, err := q.file.ReadAt(flag, off); err != nil {
		return ""
	}
	if flag[0] == 2 {
		redirectOff := make([]byte, 3)
		q.file.ReadAt(redirectOff, off+1)
		newOff := int64(readUint24(redirectOff))
		return q.readCString(newOff)
	}
	// 回退 1 字节读取普通字符串
	return q.readCString(off)
}

// readCString 读取以 null(0x00) 结尾的字节序列并 GBK->UTF8 解码
// 对应 PHP while(($char = fread($fd, 1)) != chr(0)) $ipAddr .= $char
func (q *QQWry) readCString(off int64) string {
	// 分块读取直到遇到 0x00
	var buf []byte
	chunk := make([]byte, 64)
	pos := off
	for {
		n, err := q.file.ReadAt(chunk, pos)
		if err != nil && err != io.EOF {
			break
		}
		if n == 0 {
			break
		}
		for i := 0; i < n; i++ {
			if chunk[i] == 0 {
				// 命中 null，返回已累积内容
				buf = append(buf, chunk[:i]...)
				return gbkBytesToString(buf)
			}
		}
		buf = append(buf, chunk[:n]...)
		pos += int64(n)
		if err == io.EOF {
			break
		}
	}
	return gbkBytesToString(buf)
}

// readUint24 读取 3 字节小端无符号整数
// 对应 PHP implode('', unpack('L', $data.chr(0)))
func readUint24(b []byte) uint32 {
	if len(b) < 3 {
		return 0
	}
	return uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16
}

// gbkBytesToString GBK 字节转 UTF-8 字符串
// 对应 PHP gbk_to_utf8()
func gbkBytesToString(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	out, err := gbkDecoder.Bytes(b)
	if err != nil {
		return string(b)
	}
	return string(out)
}

// joinAddr 拼接地区1与地区2
func joinAddr(addr1, addr2 string) string {
	addr1 = strings.TrimSpace(addr1)
	addr2 = strings.TrimSpace(addr2)
	if addr2 == "" {
		return addr1
	}
	return addr1 + " " + addr2
}

// cleanLocation 清洗归属地结果
// 对应 PHP convertip() 末尾的清洗：去除 CZ88.NET、控制字符、http 标记等
func cleanLocation(ip, loc string) string {
	if loc == "" {
		return "-"
	}
	// 去除 CZ88.NET 标记
	loc = strings.ReplaceAll(loc, "CZ88.NET", "")
	// 去除 http 相关标记
	if strings.Contains(strings.ToLower(loc), "http") {
		loc = ""
	}
	// 折叠空白
	loc = strings.TrimSpace(loc)
	// 过滤控制字符（0x00-0x1F, 0x7F）
	loc = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7F {
			return -1
		}
		return r
	}, loc)
	if loc == "" {
		return "-"
	}
	return loc
}

// 缓存读写

func (q *QQWry) getCache(ip string) string {
	q.cacheMu.RLock()
	defer q.cacheMu.RUnlock()
	return q.cache[ip]
}

func (q *QQWry) setCache(ip, loc string) {
	q.cacheMu.Lock()
	defer q.cacheMu.Unlock()
	if len(q.cache) >= q.cacheSize {
		// 简单淘汰：满则清空重建（生产可换 LRU）
		q.cache = make(map[string]string, 1024)
	}
	q.cache[ip] = loc
}
