package main

import (
	"aegishook/internal/assets"
	"aegishook/internal/core"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

func runClient(args []string, input io.Reader, output io.Writer) error {
	if len(args) > 0 && args[0] == "secret-resolve" {
		return runSecretResolve(args[1:], input, output)
	}
	if len(args) > 0 && args[0] == "repair" {
		return runClientRepair(args[1:], output)
	}
	if len(args) > 0 && args[0] == "discover" {
		return runClientDiscover(args[1:], output)
	}
	if len(args) > 0 && (args[0] == "codex-config" || args[0] == "codex-requirements") {
		return runCodexConfig(args[0], args[1:], output)
	}
	if len(args) == 0 || (args[0] != "install" && args[0] != "uninstall") {
		return errors.New("用法：aegishook client install|uninstall --agent AGENT --scope global|project [选项]")
	}
	action := args[0]
	f := flag.NewFlagSet("client "+action, flag.ContinueOnError)
	f.SetOutput(output)
	home, _ := os.UserHomeDir()
	o := core.ClientOptions{Progress: os.Stderr}
	f.StringVar(&o.Dir, "client-dir", filepath.Join(home, ".aegishook-client"), "Hook 客户端私有目录（不是服务端数据目录）")
	f.StringVar(&o.Agent, "agent", "claude", "pi, claude, codex, opencode, grok, cursor")
	f.StringVar(&o.Scope, "scope", "global", "global or project; Cursor also supports enterprise (staged configuration)")
	f.StringVar(&o.Project, "project", "", "项目绝对路径")
	f.StringVar(&o.PiDir, "agent-dir", core.AgentDir(), "Pi 用户目录")
	codeFile := ""
	codeStdin := false
	if action == "install" {
		f.StringVar(&o.Endpoint, "endpoint", "", "风控服务源站地址：HTTPS，或回环 HTTP")
		f.StringVar(&codeFile, "code-file", "", "一次性设备接入码文件")
		f.BoolVar(&codeStdin, "code-stdin", false, "从标准输入读取一次性接入码")
		f.BoolVar(&o.Switch, "switch", false, "安装成功时移除同一 Agent 的另一类范围（global/project）")
	}
	if e := f.Parse(args[1:]); e != nil {
		if errors.Is(e, flag.ErrHelp) {
			return nil
		}
		return e
	}
	if f.NArg() != 0 {
		return errors.New("不支持的位置参数")
	}
	if action == "install" {
		binary, err := os.Executable()
		if err != nil {
			return err
		}
		if err = refusePackageClient(binary, core.PackageRoot()); err != nil {
			return err
		}
		if codeFile != "" && codeStdin {
			return errors.New("--code-file 与 --code-stdin 不能同时提供")
		}
		source := input
		if codeFile != "" {
			file, e := os.Open(codeFile)
			if e != nil {
				return errors.New("无法读取一次性接入码文件")
			}
			defer file.Close()
			source = file
		}
		var b []byte
		var e error
		if codeFile != "" || codeStdin {
			b, e = io.ReadAll(io.LimitReader(source, 8193))
		}
		if e != nil || len(b) > 8192 {
			return errors.New("无法读取一次性接入码或接入码过长")
		}
		o.EnrollmentCode = strings.TrimSpace(string(b))
		o.Binary, e = os.Executable()
		if e != nil {
			return e
		}
		o.Resources = map[string][]byte{}
		for name, resource := range map[string]string{"index.ts": "adapter.ts", "opencode.mjs": "opencode.mjs"} {
			b, e := assets.Files.ReadFile(resource)
			if e != nil {
				return e
			}
			o.Resources[name] = b
		}
	}
	result, e := core.ClientOperation(action, o)
	if e != nil {
		return e
	}
	if e = json.NewEncoder(output).Encode(result); e != nil {
		return e
	}
	fmt.Fprintln(output, "请重载或重启 Agent；安装不改变客户端的 Hook 信任设置。")
	return nil
}

func runClientRepair(args []string, output io.Writer) error {
	if len(args) != 0 {
		return errors.New("usage: aegishook client repair (no scope or enrollment flags)")
	}
	binary, err := os.Executable()
	if err != nil {
		return err
	}
	if err = refusePackageClient(binary, core.PackageRoot()); err != nil {
		return err
	}
	account, err := currentCtlUser()
	if err != nil {
		return err
	}
	if account == nil || account.Uid == "0" || account.Uid == "S-1-5-18" || os.Getenv("SUDO_USER") != "" || os.Getenv("SUDO_UID") != "" {
		return errors.New("client repair must run as the enrolled user, without sudo")
	}
	result, err := core.ClientRepair(account.HomeDir)
	if err != nil {
		return err
	}
	return json.NewEncoder(output).Encode(result)
}
