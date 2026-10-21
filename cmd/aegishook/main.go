package main

import (
	"aegishook/internal/assets"
	"aegishook/internal/bridge"
	"aegishook/internal/core"
	"aegishook/internal/localaddr"
	"aegishook/internal/server"
	"aegishook/internal/service"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const cliTokenFile = "cli.token"

func main() {
	started := time.Now()
	if len(os.Args) > 2 && os.Args[1] == "client" && os.Args[2] == "secret-resolve" {
		if err := runSecretResolveBefore(os.Args[3:], os.Stdin, os.Stdout, started.Add(secretResolveTimeout)); err != nil {
			fmt.Fprintln(os.Stderr, errSecretResolve)
			os.Exit(1)
		}
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "server" {
		if err := runServerKeys(os.Args[2:], os.Stdout); err != nil {
			fmt.Fprintln(os.Stderr, core.RedactText(err.Error()))
			os.Exit(1)
		}
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "ctl" {
		os.Exit(runCtl(os.Args[2:], os.Stdout))
	}
	if len(os.Args) > 1 && os.Args[1] == "service" {
		if err := service.Run(core.DefaultRoot()); err != nil {
			fmt.Fprintln(os.Stderr, core.RedactText(err.Error()))
			os.Exit(1)
		}
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "client" {
		if err := runClient(os.Args[2:], os.Stdin, os.Stdout); err != nil {
			fmt.Fprintln(os.Stderr, core.RedactText(err.Error()))
			os.Exit(1)
		}
		return
	}
	if len(os.Args) > 1 && (os.Args[1] == "version" || os.Args[1] == "--version") {
		fmt.Printf("AegisHook %s (Hook %s)\n", core.ReleaseVersion, core.Version)
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "hook" {
		f := flag.NewFlagSet("hook", flag.ContinueOnError)
		agent := f.String("agent", "", "客户端类型")
		connection := f.String("connection", "", "连接配置")
		reviewID := f.String("review-id", "", "Existing review for the transform_tool_output operation")
		if err := f.Parse(os.Args[2:]); err != nil {
			if errors.Is(err, flag.ErrHelp) {
				return
			}
			os.Exit(2)
		}
		if *reviewID != "" {
			os.Exit(bridge.RunToolOutput(*connection, *reviewID, os.Stdin, os.Stdout, os.Stderr))
		}
		os.Exit(bridge.Run(*agent, *connection, os.Stdin, os.Stdout, os.Stderr))
	}
	if err := run(); err != nil {
		log.Fatal(err)
	}
}
func run() error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return runWithContext(ctx)
}

func runWithContext(ctx context.Context) error {
	if len(os.Args) > 1 && os.Args[1] == "admin" {
		return runAdmin(os.Args[2:], os.Stdout)
	}
	o, err := parseOptions(os.Args[1:], os.Stdout)
	if errors.Is(err, flag.ErrHelp) {
		return nil
	}
	if err != nil {
		return err
	}
	if o.command == "eval" {
		return runEval(context.Background(), o)
	}
	if o.command != "serve" {
		if ok, err := remoteCommand(o.command, o.dataDir, o.addr, o.scope, o.project, o.id, o.agent); ok {
			return err
		}
	}
	e, err := core.Open(o.dataDir)
	if err != nil {
		return err
	}
	defer e.Close()
	delivery, err := e.LogDeliveryStatus(context.Background())
	if err != nil {
		return err
	}
	if delivery.Pending != 0 {
		log.Printf("log delivery backlog: pending=%d held=%d oldest=%s", delivery.Pending, delivery.Held, delivery.Oldest.Format(time.RFC3339Nano))
	}
	admin, err := e.Secret(strings.TrimSuffix(cliTokenFile, ".token"))
	if err != nil {
		return err
	}
	hook, err := e.Secret("hook")
	if err != nil {
		return err
	}
	code, err := assets.Files.ReadFile("adapter.ts")
	if err != nil {
		return err
	}
	if err = e.PrepareAdapter(code, "http://"+o.addr, hook); err != nil {
		return err
	}
	plugin, err := assets.Files.ReadFile("opencode.mjs")
	if err != nil {
		return err
	}
	binary, err := os.Executable()
	if err != nil {
		return err
	}
	if err = e.PrepareIntegrations(plugin, binary); err != nil {
		return err
	}
	switch o.command {
	case "install":
		v, err := e.InstallAgent(core.WithActor(context.Background(), core.SystemActor("cli")), o.agent, o.scope, o.project, o.agentDir)
		if err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(v)
	case "uninstall":
		if o.id == "" {
			return fmt.Errorf("请用 --id 指定 status 中的安装记录")
		}
		return e.Uninstall(core.WithActor(context.Background(), core.SystemActor("cli")), o.id)
	case "status":
		is, err := e.Installations()
		if err != nil {
			return err
		}
		instances, err := e.Instances()
		if err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(map[string]any{"agents": core.DetectAgents(), "installations": is, "instances": instances})
	case "serve":
	default:
		return fmt.Errorf("支持 serve、install、uninstall、status")
	}
	ui, err := fs.Sub(assets.Files, "ui")
	if err != nil {
		return err
	}
	s := server.New(e, ui, admin, hook, o.agentDir)
	s.PublicURL = o.publicURL
	s.ClientBinaryDir = o.clientBinaries
	if o.trustedProxy != "" {
		s.TrustedProxies = strings.Split(o.trustedProxy, ",")
	}
	s.DownloadID, err = server.InitializeClientDownloads(e)
	if err != nil {
		return err
	}
	listener, err := net.Listen("tcp", o.addr)
	if err != nil {
		return err
	}
	s.ListenAddr = listener.Addr().String()
	fmt.Printf("AegisHook %s: http://%s\n控制台请使用单点登录；%s 中的令牌仅供本机 CLI 使用。\n", core.ReleaseVersion, o.addr, filepath.Join(e.Dir, cliTokenFile))
	// Serve-only: CLI subcommands (install/status/…) return before this branch, so
	// they never start the retention worker. stopRetention is deferred after
	// e.Close, so LIFO shutdown cancels and joins it before the database closes.
	stopRetention := startRetentionPurge(ctx, e)
	defer stopRetention()
	return serveHTTP(ctx, listener, s.Handler())
}

// serveHTTP serves until ctx is cancelled, then drains: request contexts derive from baseCtx, which is
// cancelled when shutdown starts so long-lived SSE streams end instead of holding Shutdown to its
// deadline, and it returns only after Shutdown has finished, so after a successful drain the caller's
// deferred engine close cannot race in-flight requests. If the drain deadline passes, Close drops the
// remaining connections without waiting for handler cleanup (https://pkg.go.dev/net/http#Server.Shutdown).
func serveHTTP(ctx context.Context, listener net.Listener, handler http.Handler) error {
	baseCtx, cancelRequests := context.WithCancel(context.Background())
	defer cancelRequests()
	httpServer := &http.Server{Handler: handler, ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 60 * time.Second,
		BaseContext: func(net.Listener) context.Context { return baseCtx }}
	httpServer.RegisterOnShutdown(cancelRequests)
	shutdownDone := make(chan error, 1)
	go func() {
		<-ctx.Done()
		c, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		err := httpServer.Shutdown(c)
		if err != nil {
			err = errors.Join(err, httpServer.Close())
		}
		shutdownDone <- err
	}()
	if err := httpServer.Serve(listener); err != http.ErrServerClosed {
		return err
	}
	return <-shutdownDone
}

func remoteCommand(command, data, addr, scope, project, id, agent string) (bool, error) {
	host, port, err := net.SplitHostPort(addr)
	portNumber, portErr := strconv.Atoi(port)
	if err != nil || !localaddr.IsLoopback(host) || portErr != nil || portNumber < 1 || portNumber > 65535 {
		return true, fmt.Errorf("CLI 仅支持本机回环地址和有效端口")
	}
	// Pin localhost to loopback rather than trusting DNS for a credential-bearing request.
	if strings.EqualFold(host, "localhost") {
		addr = net.JoinHostPort("127.0.0.1", port)
	}
	token, err := os.ReadFile(filepath.Join(data, cliTokenFile))
	if err != nil {
		return true, fmt.Errorf("无法读取本机 CLI 令牌 %s；请先启动服务，并确认数据目录和读取权限", cliTokenFile)
	}
	// No environment proxy or redirects: neither the token nor the cookie may leave loopback.
	transport := &http.Transport{}
	defer transport.CloseIdleConnections()
	client := &http.Client{Timeout: 5 * time.Second, Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	b, _ := json.Marshal(map[string]string{"token": string(token)})
	res, err := client.Post("http://"+addr+"/api/v1/cli/session", "application/json", bytes.NewReader(b))
	if err != nil {
		return false, nil
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		return true, fmt.Errorf("服务管理认证失败")
	}
	var cookie *http.Cookie
	for _, c := range res.Cookies() {
		if c.Name == "aegis_session" {
			cookie = c
		}
	}
	if cookie == nil {
		return true, fmt.Errorf("未收到管理会话")
	}
	endpoint := "/api/v1/installations"
	method := "GET"
	var body []byte
	switch command {
	case "install":
		method = "POST"
		body, _ = json.Marshal(map[string]string{"agent": agent, "scope": scope, "project": project})
	case "uninstall":
		if id == "" {
			return true, fmt.Errorf("请指定 --id")
		}
		method = "DELETE"
		endpoint += "/" + id
	case "status":
		values := map[string]any{}
		for _, kind := range []string{"agents", "instances", "installations"} {
			req, _ := http.NewRequest("GET", "http://"+addr+"/api/v1/"+kind, nil)
			req.AddCookie(cookie)
			res, err := client.Do(req)
			if err != nil {
				return true, err
			}
			if res.StatusCode != 200 {
				res.Body.Close()
				return true, fmt.Errorf("状态查询失败 HTTP %d", res.StatusCode)
			}
			var value any
			err = json.NewDecoder(res.Body).Decode(&value)
			res.Body.Close()
			if err != nil {
				return true, err
			}
			values[kind] = value
		}
		return true, json.NewEncoder(os.Stdout).Encode(values)
	default:
		return true, fmt.Errorf("未知命令")
	}
	req, _ := http.NewRequest(method, "http://"+addr+endpoint, bytes.NewReader(body))
	req.AddCookie(cookie)
	req.Header.Set("Content-Type", "application/json")
	out, err := client.Do(req)
	if err != nil {
		return true, err
	}
	defer out.Body.Close()
	if out.StatusCode < http.StatusOK || out.StatusCode >= http.StatusMultipleChoices {
		return true, fmt.Errorf("管理操作失败 HTTP %d", out.StatusCode)
	}
	_, err = io.Copy(os.Stdout, out.Body)
	return true, err
}

// Plan §3.6b: offline recovery, reusing core's process lock and atomic 0600 file writes.
func runAdmin(args []string, output io.Writer) error {
	if len(args) > 0 && args[0] == "help" {
		args = append(append([]string{}, args[1:]...), "-h")
	}
	action := ""
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		action, args = args[0], args[1:]
	}
	usage := errors.New("用法：aegishook admin bind|unbind --issuer ISSUER --subject SUBJECT [--data-dir DIR]；bind 可加 --name NAME")
	if action != "" && action != "bind" && action != "unbind" {
		return usage
	}
	f := flag.NewFlagSet("aegishook admin "+action, flag.ContinueOnError)
	f.SetOutput(output)
	home, _ := os.UserHomeDir()
	dir := f.String("data-dir", filepath.Join(home, ".aegishook"), "私有数据目录；请先停止服务")
	issuer := f.String("issuer", "", "OIDC 签发者地址，需与登录时的 issuer 完全一致")
	subject := f.String("subject", "", "OIDC 用户的 sub，不是邮箱或显示名称")
	name := ""
	if action == "bind" {
		f.StringVar(&name, "name", "", "显示名称（可选）")
	}
	f.Usage = func() { fmt.Fprintln(output, usage); f.PrintDefaults() }
	if err := f.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if action == "" || f.NArg() != 0 || *issuer == "" || *subject == "" {
		return usage
	}
	// Match server-keys: do not leak underlying initialization or file contents in errors.
	unavailable := errors.New("管理员绑定操作失败；请先停止服务，并检查数据目录权限和 admin-bindings.json 格式")
	e, err := core.Open(*dir)
	if err != nil {
		return unavailable
	}
	defer e.Close()
	principal := core.Principal{Issuer: *issuer, Subject: *subject}
	if action == "bind" {
		err = e.BindAdmin(principal, name)
	} else {
		err = e.UnbindAdmin(principal)
	}
	if err != nil {
		return unavailable
	}
	_, err = fmt.Fprintln(output, "管理员绑定已更新；重启服务后重新登录即可生效。")
	return err
}
