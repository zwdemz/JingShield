//go:build !linux

package main

func acquireInstanceLock() (func(), error) { return func() {}, nil }
