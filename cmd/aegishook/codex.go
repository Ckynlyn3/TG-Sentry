package main

import (
	"aegishook/internal/core"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
)

// Generate for review/deployment, never modify system requirements or user TOML.
func runCodexConfig(action string, args []string, output io.Writer) error {
	f := flag.NewFlagSet("client "+action, flag.ContinueOnError)
	f.SetOutput(output)
	binary, err := os.Executable()
	if err != nil {
		return err
	}
	connection := ""
	f.StringVar(&binary, "binary", binary, "absolute path to the endpoint AegisHook binary")
	f.StringVar(&connection, "connection", "", "absolute path to the endpoint adapter/connection.json (not read)")
	if err := f.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if f.NArg() != 0 {
		return errors.New("unexpected positional arguments")
	}
	snippet, err := core.CodexHookTOML(binary, connection, action == "codex-requirements")
	if err != nil {
		return err
	}
	_, err = fmt.Fprint(output, snippet)
	return err
}
