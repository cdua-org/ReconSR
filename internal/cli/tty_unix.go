//go:build !windows

package cli

import (
	"os"
	"syscall"
)

func getTTYPath() string {
	return "/dev/tty"
}

func getTTYOpenFlags() int {
	return os.O_RDONLY | syscall.O_NONBLOCK
}
