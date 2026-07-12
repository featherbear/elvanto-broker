package httpx

import (
	"net/http"
	"strings"
)

type CORS struct {
	allowedOrigins []string
}

func NewCORS(allowedOrigins []string) *CORS {
	return &CORS{allowedOrigins: allowedOrigins}
}

func (p *CORS) WriteHeaders(w http.ResponseWriter, r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true
	}
	if !p.originAllowed(origin) {
		return false
	}
	w.Header().Set("Access-Control-Allow-Origin", origin)
	w.Header().Set("Vary", "Origin")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
	w.Header().Set("Access-Control-Max-Age", "600")
	return true
}

func (p *CORS) originAllowed(origin string) bool {
	if len(p.allowedOrigins) == 0 {
		return true
	}
	for _, allowed := range p.allowedOrigins {
		if allowed == origin || allowed == "*" || wildcardOriginAllowed(origin, allowed) {
			return true
		}
	}
	return false
}

func wildcardOriginAllowed(origin, allowed string) bool {
	const wildcard = `://*.`
	index := strings.Index(allowed, wildcard)
	if index == -1 {
		return false
	}
	scheme := allowed[:index+3]
	suffix := allowed[index+len(wildcard)-1:]
	return strings.HasPrefix(origin, scheme) && strings.HasSuffix(origin, suffix)
}
