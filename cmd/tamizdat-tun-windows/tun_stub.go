//go:build !windows

package main

func requireWintunDLL() error { return nil }
