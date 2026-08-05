# 鲸盾规则包

## java-emergency-2026h1

`packs/java-emergency-2026h1.json` 根据 2026-02-05 至 2026-08-05 的 Java 生态官方安全公告整理，包含 8 条阻断规则与 3 条仅记录规则。

主要依据：

- [Apache Tomcat 11 安全公告](https://tomcat.apache.org/security-11)
- [Apache Tomcat 9 安全公告](https://tomcat.apache.org/security-9)
- [Fastjson CVE-2026-16723 官方安全公告](https://github.com/alibaba/fastjson2/wiki/Security-Advisory%3A-Remote-Code-Execution-in-fastjson-1.2.68%E2%80%931.2.83)
- [Spring 官方安全公告](https://spring.io/security/)
- [Apache Logging Services 安全公告](https://logging.apache.org/security.html)

规则包只处理 WAF 能看到且能稳定表达的 HTTP 特征。Tomcat 的 TLS/OCSP、AJP、集群 EncryptInterceptor、SNI、HTTP/2 帧级问题，以及应用内部鉴权逻辑不能靠正则规则修复，必须升级组件和修正配置。

导入会原子替换 `import` 来源，不影响 `custom` 和 `auto` 来源：

```bash
curl -k -b cookie.txt -H 'X-CSRF-Token: <token>' \
  -H 'Content-Type: application/json' \
  --data-binary @rules/packs/java-emergency-2026h1.json \
  https://waf.example.com/api/v1/policies/import
```

建议先在测试节点运行至少 24 小时。`action=2` 为仅记录，确认无合法业务命中后再按站点需求调整为阻断。规则是补偿控制，不能替代 Tomcat、Fastjson、Spring 和 Log4j 的安全升级。
