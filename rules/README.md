# 鲸盾规则包

## 规则包目录

| 文件 | 用途 | 建议场景 |
| --- | --- | --- |
| `packs/jingshield-baseline-2026.08.json` | 通用 HTTP 防护基线，覆盖注入、文件访问、SSRF、XML、反序列化、上传和 GraphQL | 默认导入，先观察再按业务调优 |
| `packs/java-emergency-2026h1.json` | Tomcat、Fastjson、Spring/Log4j 相关专项虚拟补丁 | 明确运行 Java 技术栈且需要紧急缓解 |

同一来源的导入是原子替换，不是追加：手工导入新文件会替换上一份 `import` 来源规则，但不会影响 `custom` 和 `auto` 来源。因此通用站点应直接选择综合基线；Java 专项包适合替代导入或按需复制其中规则为自定义策略。

## jingshield-baseline-2026.08

综合基线包含以下检测层：

- SQL、NoSQL 与命令注入
- XSS、路径穿越/LFI、SSRF 和 CRLF
- XXE/XInclude/XMLDecoder、SSTI/EL/OGNL/FreeMarker
- Fastjson、Java/PHP/.NET/Node/YAML 反序列化特征
- JavaScript 原型污染
- multipart 危险文件名、类型不一致、前 4KB 脚本/活动内容样本
- GraphQL introspection、批处理、深度、别名放大和敏感 mutation

`action=1` 是低歧义的阻断规则。NoSQL 比较操作符、SQL 堆叠语句、文件 MIME 不一致、活动 HTML/SVG、GraphQL 复杂度等依赖业务语义，默认使用 `action=2` 仅记录。建议观察至少 24 小时，再针对具体站点调整。

上传检查只分析 multipart 文件名、声明/探测 MIME、文件大小和前 4KB 内容，不保存额外文件，也不改变转发给上游的原始请求。它能发现常见脚本伪装，不能替代杀毒、沙箱、完整文件解析和上传目录隔离。

GraphQL 的深度与别名规则是 RE2 启发式检测。字段级授权、精确 AST 深度/复杂度、持久化查询和单字段成本限制必须在 GraphQL 网关或应用实现。

## java-emergency-2026h1

`packs/java-emergency-2026h1.json` 根据 2026-02-05 至 2026-08-05 的 Java 生态官方安全公告整理，包含 8 条阻断规则与 3 条仅记录规则。

主要依据：

- [Apache Tomcat 11 安全公告](https://tomcat.apache.org/security-11)
- [Apache Tomcat 9 安全公告](https://tomcat.apache.org/security-9)
- [Fastjson CVE-2026-16723 官方安全公告](https://github.com/alibaba/fastjson2/wiki/Security-Advisory%3A-Remote-Code-Execution-in-fastjson-1.2.68%E2%80%931.2.83)
- [Spring 官方安全公告](https://spring.io/security/)
- [Apache Logging Services 安全公告](https://logging.apache.org/security.html)

规则包只处理 WAF 能看到且能稳定表达的 HTTP 特征。Tomcat 的 TLS/OCSP、AJP、集群 EncryptInterceptor、SNI、HTTP/2 帧级问题，以及应用内部鉴权逻辑不能靠正则规则修复，必须升级组件和修正配置。

## 导入示例

```bash
curl -k -b cookie.txt -H 'X-CSRF-Token: <token>' \
  -H 'Content-Type: application/json' \
  --data-binary @rules/packs/jingshield-baseline-2026.08.json \
  https://waf.example.com/api/v1/policies/import
```

## 能力边界

规则包只处理 WAF 能看到且能稳定表达的 HTTP 特征。它不能精确判断数据库语义、DNS 重绑定后的 SSRF 目标、压缩包解压内容、GraphQL 字段授权或业务工作流。Tomcat 的 TLS/OCSP、AJP、集群、SNI、HTTP/2 帧级问题也不能靠正则修复。

策略是补偿控制，不替代参数化查询、上下文输出编码、安全解析器、网络出口控制、组件升级和应用侧授权。规则文件必须保持 `jingshield.rules/v1` schema，正则使用 Go RE2 语法，不支持回溯引用和前后向断言。
