package firewallbridge

import (
	"bytes"
	"context"
	"errors"
	"os/exec"
	"runtime"
	"time"
)

type commandRunner struct{}
type boundedOutput struct {
	bytes.Buffer
	limit    int
	overflow bool
}

func (b *boundedOutput) Write(value []byte) (int, error) {
	original := len(value)
	remaining := b.limit - b.Len()
	if len(value) > remaining {
		b.overflow = true
		value = value[:max(remaining, 0)]
	}
	_, _ = b.Buffer.Write(value)
	return original, nil
}

func (commandRunner) Run(ctx context.Context, executable string, args []string, input []byte) ([]byte, error) {
	if runtime.GOOS != "linux" {
		return nil, errors.New("firewall apply is supported on Linux only")
	}
	if executable != "/usr/sbin/nft" && executable != "/usr/sbin/ipset" {
		return nil, errors.New("unapproved firewall executable")
	}
	command := exec.CommandContext(ctx, executable, args...)
	command.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C"}
	command.Stdin = bytes.NewReader(input)
	stdout := &boundedOutput{limit: 4 << 20}
	stderr := &boundedOutput{limit: 16 << 10}
	command.Stdout = stdout
	command.Stderr = stderr
	command.WaitDelay = time.Second
	if err := command.Run(); err != nil {
		return nil, errors.New("firewall command failed; inspect adapter and kernel configuration")
	}
	if stdout.overflow || stderr.overflow {
		return nil, errors.New("firewall command output exceeded bound")
	}
	return stdout.Bytes(), nil
}
