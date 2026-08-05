package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"jingshield/internal/api"
	"jingshield/internal/config"
	"jingshield/internal/iplib"
	"jingshield/internal/pkg/logx"
	"jingshield/internal/policy"
	"jingshield/internal/protection"
	"jingshield/internal/protection/cc"
	"jingshield/internal/protection/iplist"
	"jingshield/internal/protection/verify"
	"jingshield/internal/proxy"
	"jingshield/internal/repository"
	"jingshield/internal/store/memory"
	webui "jingshield/web"
)

type unavailableLocator struct{}

func (unavailableLocator) Lookup(string) string { return "" }
func (unavailableLocator) Available() bool      { return false }

func main() {
	if err := execute(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return
		}
		fmt.Fprintln(os.Stderr, "jingshield 执行失败:", err)
		os.Exit(1)
	}
}

func execute(args []string, stdout, stderr io.Writer) error {
	command := "serve"
	if len(args) > 0 && args[0] != "" && args[0][0] != '-' {
		command = args[0]
		args = args[1:]
	}

	switch command {
	case "serve":
		fs := flag.NewFlagSet("serve", flag.ContinueOnError)
		fs.SetOutput(stderr)
		configPath := configFlag(fs)
		if err := fs.Parse(args); err != nil {
			return err
		}
		if fs.NArg() != 0 {
			return fmt.Errorf("serve 不接受位置参数: %v", fs.Args())
		}
		return run(*configPath)

	case "migrate":
		fs := flag.NewFlagSet("migrate", flag.ContinueOnError)
		fs.SetOutput(stderr)
		configPath := configFlag(fs)
		if err := fs.Parse(args); err != nil {
			return err
		}
		if fs.NArg() != 0 {
			return fmt.Errorf("migrate 不接受位置参数: %v", fs.Args())
		}
		return runMigrate(*configPath, stdout)

	case "init":
		fs := flag.NewFlagSet("init", flag.ContinueOnError)
		fs.SetOutput(stderr)
		configPath := configFlag(fs)
		username := fs.String("username", "admin", "初始管理员用户名")
		email := fs.String("email", "", "初始管理员邮箱（可选）")
		if err := fs.Parse(args); err != nil {
			return err
		}
		if fs.NArg() != 0 {
			return fmt.Errorf("init 不接受位置参数: %v", fs.Args())
		}
		return runInit(*configPath, *username, *email, stdout)

	case "cert":
		fs := flag.NewFlagSet("cert", flag.ContinueOnError)
		fs.SetOutput(stderr)
		certPath := fs.String("cert", "jingshield.crt", "PEM 证书输出路径")
		keyPath := fs.String("key", "jingshield.key", "PEM 私钥输出路径")
		hosts := fs.String("hosts", "localhost,127.0.0.1", "证书 SAN，逗号分隔的域名或 IP")
		days := fs.Int("days", 10950, "有效天数")
		if err := fs.Parse(args); err != nil {
			return err
		}
		if fs.NArg() != 0 {
			return fmt.Errorf("cert 不接受位置参数: %v", fs.Args())
		}
		return runCert(*certPath, *keyPath, strings.Split(*hosts, ","), *days, stdout)

	case "help":
		printUsage(stdout)
		return nil
	default:
		printUsage(stderr)
		return fmt.Errorf("未知命令 %q", command)
	}
}

func configFlag(fs *flag.FlagSet) *string {
	var path string
	fs.StringVar(&path, "config", "configs/config.yaml", "配置文件路径")
	fs.StringVar(&path, "c", "configs/config.yaml", "配置文件路径（简写）")
	return &path
}

func printUsage(w io.Writer) {
	fmt.Fprintln(w, "用法:")
	fmt.Fprintln(w, "  jingshield [-c config.yaml]                 启动 WAF")
	fmt.Fprintln(w, "  jingshield migrate [-c config.yaml]         创建/补齐数据库结构")
	fmt.Fprintln(w, "  jingshield init [-c config.yaml] [选项]     初始化管理员和 API Key")
	fmt.Fprintln(w, "  jingshield cert [选项]                     生成 PEM 自签名测试证书")
}

func runCert(certPath, keyPath string, hosts []string, days int, stdout io.Writer) error {
	if certPath == "" || keyPath == "" || filepath.Clean(certPath) == filepath.Clean(keyPath) {
		return errors.New("证书和私钥路径不能为空且不能相同")
	}
	if days < 1 || days > 36500 {
		return errors.New("证书有效天数必须为 1-36500")
	}
	for _, path := range []string{certPath, keyPath} {
		if _, err := os.Stat(path); err == nil {
			return fmt.Errorf("拒绝覆盖已有文件: %s", path)
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		if err := os.MkdirAll(filepath.Dir(path), 0750); err != nil {
			return err
		}
	}

	var dnsNames []string
	var ipAddresses []net.IP
	for _, raw := range hosts {
		host := strings.TrimSpace(raw)
		if host == "" {
			continue
		}
		if ip := net.ParseIP(host); ip != nil {
			ipAddresses = append(ipAddresses, ip)
		} else {
			dnsNames = append(dnsNames, host)
		}
	}
	if len(dnsNames) == 0 && len(ipAddresses) == 0 {
		return errors.New("至少提供一个有效的域名或 IP SAN")
	}
	commonName := ""
	if len(dnsNames) > 0 {
		commonName = dnsNames[0]
	} else if len(ipAddresses) > 0 {
		commonName = ipAddresses[0].String()
	}
	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return err
	}
	privateKey, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		return fmt.Errorf("生成 RSA 私钥失败: %w", err)
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: commonName, Organization: []string{"JingShield Test"}},
		NotBefore: now.Add(-5 * time.Minute), NotAfter: now.Add(time.Duration(days) * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true, DNSNames: dnsNames, IPAddresses: ipAddresses,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return fmt.Errorf("生成证书失败: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
		return err
	}
	if err := os.WriteFile(certPath, certPEM, 0644); err != nil {
		_ = os.Remove(keyPath)
		return err
	}
	fmt.Fprintf(stdout, "自签名测试证书已生成：%s（%d 天），私钥：%s\n", certPath, days, keyPath)
	return nil
}

func openMigratedDB(ctx context.Context, configPath string) (*config.Config, *sql.DB, error) {
	cfg, err := config.Load(configPath)
	if err != nil {
		return nil, nil, err
	}
	if err := repository.EnsureDatabase(cfg.Database); err != nil {
		return nil, nil, err
	}
	db, err := repository.NewDB(cfg.Database)
	if err != nil {
		return nil, nil, err
	}
	if err := repository.Migrate(ctx, db); err != nil {
		db.Close()
		return nil, nil, err
	}
	return cfg, db, nil
}

func runMigrate(configPath string, stdout io.Writer) error {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	cfg, db, err := openMigratedDB(ctx, configPath)
	if err != nil {
		return err
	}
	defer db.Close()
	fmt.Fprintf(stdout, "数据库 %s 迁移完成（10 张业务表及默认配置）\n", cfg.Database.Name)
	return nil
}

func runInit(configPath, username, email string, stdout io.Writer) error {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	_, db, err := openMigratedDB(ctx, configPath)
	if err != nil {
		return err
	}
	defer db.Close()
	credentials, err := repository.Initialize(ctx, db, username, email)
	if err != nil {
		return err
	}
	fmt.Fprintln(stdout, "系统初始化完成。以下凭据只显示一次，请立即安全保存：")
	fmt.Fprintf(stdout, "管理员用户名: %s\n", credentials.Username)
	fmt.Fprintf(stdout, "管理员密码: %s\n", credentials.Password)
	fmt.Fprintf(stdout, "设备 API Key: %s\n", credentials.APIKey)
	return nil
}

func run(configPath string) error {
	cfg, err := config.Load(configPath)
	if err != nil {
		return err
	}
	if err := logx.Init(logx.Config{
		Level: cfg.Log.Level, Dir: cfg.Log.Dir, MaxSizeMB: cfg.Log.MaxSizeMB,
		MaxBackups: cfg.Log.MaxBackups, MaxAgeDays: cfg.Log.MaxAgeDays,
	}); err != nil {
		return err
	}

	db, err := repository.NewDB(cfg.Database)
	if err != nil {
		return err
	}
	defer db.Close()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := repository.Migrate(ctx, db); err != nil {
		return fmt.Errorf("数据库自动迁移失败: %w", err)
	}

	dynCfg := config.NewDynamicConfig(db)
	if err := dynCfg.Load(ctx); err != nil {
		return fmt.Errorf("加载动态配置失败: %w", err)
	}
	dynCfg.StartAutoReload(ctx, 30*time.Second)

	var locator iplib.Locator = unavailableLocator{}
	if qqwry, openErr := iplib.NewQQWry(cfg.Data.QQWryDat); openErr != nil {
		logx.Warn("QQWry 数据不可用，IP 归属地与海外 IP 检测将降级", "err", openErr)
	} else {
		locator = qqwry
		defer qqwry.Close()
	}

	state := memory.New()
	gcInterval := time.Duration(cfg.Data.StateGCInterval) * time.Second
	state.StartGC(ctx, gcInterval, 10*time.Minute)
	cc.StartCPUMonitor(ctx)

	accessRepo := repository.NewAccessLogRepo(db)
	attackRepo := repository.NewAttackLogRepo(db)
	ipListRepo := repository.NewIPListRepo(db)
	verifyFailRepo := repository.NewVerifyFailRepo(db)
	siteRepo := repository.NewSiteRepo(db)
	policyRepo := repository.NewPolicyRepo(db)
	policySvc := policy.New(policyRepo, dynCfg)
	policySvc.StartAutoUpdate(ctx)
	ipListSvc := iplist.New(ipListRepo, locator, dynCfg)
	verifySvc := verify.New(verifyFailRepo, ipListRepo, state, dynCfg, cfg.Session)
	ccDetector := cc.NewCCDetector(state, accessRepo, verifyFailRepo, ipListRepo, locator, dynCfg, cfg.Session)
	engine := protection.NewEngine(dynCfg, ipListSvc, ccDetector, verifySvc, accessRepo, attackRepo, locator, policySvc)
	proxyHandler, err := proxy.New(engine, verifySvc, dynCfg, siteRepo, cfg.Upstream, cfg.Server)
	if err != nil {
		return err
	}
	handler, err := api.New(api.Dependencies{
		DB: db, DynamicConfig: dynCfg, State: state, StaticConfig: cfg, Sites: siteRepo,
		Policies: policySvc, AdminHandler: webui.Handler(), FallbackHandler: proxyHandler,
	})
	if err != nil {
		return err
	}

	newServer := func(addr string) *http.Server {
		return &http.Server{
			Addr: addr, Handler: handler, ReadHeaderTimeout: 10 * time.Second,
			ReadTimeout:  time.Duration(cfg.Server.ReadTimeout) * time.Second,
			WriteTimeout: time.Duration(cfg.Server.WriteTimeout) * time.Second,
			IdleTimeout:  90 * time.Second,
		}
	}
	servers := []*http.Server{newServer(cfg.Server.Listen)}
	errCh := make(chan error, 2)
	go func() {
		logx.Info("捷云鲸盾已启动", "listen", cfg.Server.Listen, "upstream", cfg.Upstream.Target)
		errCh <- servers[0].ListenAndServe()
	}()
	if cfg.Server.TLSListen != "" {
		tlsServer := newServer(cfg.Server.TLSListen)
		servers = append(servers, tlsServer)
		go func() {
			logx.Info("捷云鲸盾 HTTPS 已启动", "listen", cfg.Server.TLSListen)
			errCh <- tlsServer.ListenAndServeTLS(cfg.Server.TLSCertFile, cfg.Server.TLSKeyFile)
		}()
	}

	shutdown := func() error {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		var shutdownErr error
		for _, server := range servers {
			if err := server.Shutdown(shutdownCtx); err != nil && shutdownErr == nil {
				shutdownErr = err
			}
		}
		return shutdownErr
	}

	select {
	case <-ctx.Done():
		if err := shutdown(); err != nil {
			return fmt.Errorf("服务关闭失败: %w", err)
		}
		return nil
	case err := <-errCh:
		_ = shutdown()
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}
