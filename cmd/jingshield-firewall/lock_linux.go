//go:build linux

package main

import (
	"errors"
	"golang.org/x/sys/unix"
	"os"
)

func acquireInstanceLock() (func(), error) {
	file, err := os.OpenFile("/run/jingshield-firewall/adapter.lock", os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, errors.New("create private /run/jingshield-firewall directory before starting adapter")
	}
	if unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB) != nil {
		file.Close()
		return nil, errors.New("another firewall adapter owns the exclusive lock")
	}
	return func() { _ = unix.Flock(int(file.Fd()), unix.LOCK_UN); _ = file.Close() }, nil
}
