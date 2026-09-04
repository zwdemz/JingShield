# JingShield 管理界面

## 环境

- Node.js 20.19+ 或 22.12+
- npm 10+
- 已启动的 JingShield Go 服务（默认 `http://127.0.0.1:18080`）

## 开发

```powershell
npm install
$env:JINGSHIELD_DEV_API='http://127.0.0.1:18080'
npm run dev
```

浏览器访问 `http://127.0.0.1:5173/admin/`。开发服务器将 `/api` 转发到 `JINGSHIELD_DEV_API`，不模拟登录、CSRF 或业务数据。

## 生产构建

```powershell
npm run build
cd ..
go build -o bin/jingshield.exe ./cmd/jingshield
```

Vite 产物位于 `web/dist`，由 `web/embed.go` 编译进 Go 二进制。生产入口为 `/admin/`；静态页面与管理 API 都受后端 `admin_ips` 白名单约束。

## 检查

```powershell
npm run build
cd ..
go test ./...
go vet ./...
```
