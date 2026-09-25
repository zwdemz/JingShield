# Docker 测试部署

此栈仅用于隔离验收：MySQL 与上游 Nginx 不暴露主机端口，鲸盾默认绑定 NAS 的 `192.168.1.92:18081`（HTTP）及 `192.168.1.92:18443`（HTTPS）。其他机器可设置 `JINGSHIELD_BIND_IP` 覆盖绑定地址。管理页仅放行配置文件所列的客户端地址；测试机的地址应按需调整。不要将测试数据库或凭据用于生产。

实际部署的域名回源映射可通过 Compose `extra_hosts` 设置。NAS 专用编排配置保存在不提交版本控制的 `compose.nas.local.yaml` 时，请将下文命令中的 `compose.test.yaml` 替换为该文件名。

在项目根目录构建镜像：

```sh
docker build -t jingshield:test-20260924 .
```

若测试机无法拉取 Node/Go/Debian 基础镜像，可先在有 Go 1.25 与 Node 22 的构建机执行 `cd web && npm ci && npm run build`，再于项目根目录交叉编译 `CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags='-s -w' -o deploy/docker/jingshield-linux-amd64 ./cmd/jingshield`。将该文件及测试机的 `/etc/ssl/certs/ca-certificates.crt` 放入 `deploy/docker/` 后，可在项目根目录构建不依赖远端基础镜像的测试镜像：

```sh
docker build -f deploy/docker/Dockerfile.test-binary -t jingshield:test-20260924 .
```

这个备用镜像仅供隔离验收；正式交付应使用根目录的多阶段 `Dockerfile`。

首次启动前生成仅供本测试栈使用的随机凭据：

```sh
sh deploy/docker/prepare-test-env.sh deploy/docker
sudo install -d -o 10001 -g 10001 -m 700 deploy/docker/data/waf/tls
sudo openssl req -x509 -nodes -newkey rsa:3072 -sha256 -days 30 -keyout deploy/docker/data/waf/tls/lan.key -out deploy/docker/data/waf/tls/lan.crt -subj /CN=192.168.1.92 -addext subjectAltName=IP:192.168.1.92
sudo chown 10001:10001 deploy/docker/data/waf/tls/lan.key deploy/docker/data/waf/tls/lan.crt
sudo chmod 600 deploy/docker/data/waf/tls/lan.key
cd deploy/docker
docker compose --env-file .env.test -f compose.test.yaml config -q
docker compose --env-file .env.test -f compose.test.yaml up -d
docker compose --env-file .env.test -f compose.test.yaml ps
```

数据库和应用日志分别保存在 `deploy/docker/data/mysql` 与 `deploy/docker/data/waf`。`.env.test` 须保持仅所有者可读，不能提交到版本控制。

从 NAS 或同一局域网验证反向代理：

```sh
curl -i http://192.168.1.92:18081/
```

管理页请使用 `https://192.168.1.92:18443/admin/`。测试证书为自签名，有效期 30 天，浏览器首次访问会提示不受信任；正式部署应使用受信任的证书。

检查日志：

```sh
docker compose --env-file .env.test -f compose.test.yaml logs --tail=100 waf
```

停止测试栈而保留数据：

```sh
docker compose --env-file .env.test -f compose.test.yaml down
```

回滚到先前镜像时，先停止测试栈，再改回先前镜像标签并重新执行 `up -d`；绑定目录中的数据库和日志不会因 `down` 删除。生产部署应单独配置 HTTPS、真实上游和访问控制，不应直接使用此测试 Compose。
