// SPDX-FileCopyrightText: 2026 Avinash Rajendra Patil
// SPDX-License-Identifier: MIT

package main

import (
	"os"

	"github.com/Avi6855/debsmith/internal/cli"
)

func main() {
	os.Exit(cli.Execute(os.Args[1:]))
}
