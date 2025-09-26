package middleware

import (
	"time"

	"github.com/labstack/echo/v4"
	"github.com/maypok86/otter"
	"github.com/starfederation/datastar-go/datastar"
)

func LoginRateLimiter() echo.MiddlewareFunc {
	rateLimitCacheBuilder, _ := otter.NewBuilder[string, int32](10_000)

	rateLimit, _ := rateLimitCacheBuilder.WithTTL(10 * time.Minute).Build()

	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) (err error) {
			ip := c.RealIP()

			hits, found := rateLimit.Get(ip)
			if !found {
				if ok := rateLimit.Set(ip, 1); !ok {
					return next(c)
				}
			}
			if hits <= 5 {
				if ok := rateLimit.Set(ip, hits+1); !ok {
					return next(c)
				}
			}

			if hits > 5 {
				sse := datastar.NewSSE(c.Response(), c.Request())
				sse.PatchElements(
					"<p class='text-error-content'>Too many login attempts from your IP address. Please try again later.</p>",
					datastar.WithSelectorID("loginRes"),
					datastar.WithModeInner(),
				)
			}

			return next(c)
		}
	}
}
