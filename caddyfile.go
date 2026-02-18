package checkandredirect

import (
	"strconv"

	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func init() {
	httpcaddyfile.RegisterHandlerDirective("check_and_redirect", parseCaddyfile)
	// Register the directive order: place it before respond.
	httpcaddyfile.RegisterDirectiveOrder("check_and_redirect", httpcaddyfile.Before, "respond")
}

// parseCaddyfile parses the Caddyfile tokens for the check_and_redirect directive.
//
// Syntax:
//
//	check_and_redirect {
//	    file <path>
//	    status <301|302>
//	    schedule <minutes>
//	}
// go mod init caddy
// go mod edit -require github.com/Lukino2000/caddy-check-and-redirect@v0.0.0
// go mod edit -replace github.com/Lukino2000/caddy-check-and-redirect=../../
// go mod tidy
func parseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var cr CheckAndRedirect

	for h.Next() {
		// There should be no arguments on the same line as the directive.
		if h.NextArg() {
			return nil, h.ArgErr()
		}

		for h.NextBlock(0) {
			switch h.Val() {
			case "file":
				if !h.NextArg() {
					return nil, h.ArgErr()
				}
				cr.File = h.Val()

			case "status":
				if !h.NextArg() {
					return nil, h.ArgErr()
				}
				status, err := strconv.Atoi(h.Val())
				if err != nil {
					return nil, h.Errf("invalid status code: %v", err)
				}
				if status != 301 && status != 302 {
					return nil, h.Errf("status must be 301 or 302, got %d", status)
				}
				cr.Status = status

			case "schedule":
				if !h.NextArg() {
					return nil, h.ArgErr()
				}
				schedule, err := strconv.Atoi(h.Val())
				if err != nil {
					return nil, h.Errf("invalid schedule value: %v", err)
				}
				if schedule <= 0 {
					return nil, h.Errf("schedule must be greater than 0, got %d", schedule)
				}
				cr.Schedule = schedule

			default:
				return nil, h.Errf("unknown subdirective '%s'", h.Val())
			}
		}
	}

	return &cr, nil
}
