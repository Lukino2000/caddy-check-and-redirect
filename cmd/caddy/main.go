package main

import (
	caddycmd "github.com/caddyserver/caddy/v2/cmd"

	// Plug in Caddy modules here.
	_ "github.com/caddyserver/caddy/v2/modules/standard"

	// Plug in the check_and_redirect module.
	_ "github.com/Lukino2000/caddy-check-and-redirect"
)

func main() {
	caddycmd.Main()
}