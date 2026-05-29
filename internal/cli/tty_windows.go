//go:build windows

package cli

import (
	"os"
)

func getTTYPath() string {
	return "CONIN$"
}

func getTTYOpenFlags() int {
	return os.O_RDONLY
}
