package transport

import (
	"net/http"
	"strings"
)

// ExtractToken pulls the JWT from the request, checking in order:
// 1. Authorization: Bearer <token> header
// 2. ?token=<token> query parameter
func ExtractToken(r *http.Request) string {
	// Check Authorization header first.
	authHeader := r.Header.Get("Authorization")
	if strings.HasPrefix(authHeader, "Bearer ") {
		return strings.TrimPrefix(authHeader, "Bearer ")
	}

	// Fall back to query parameter.
	return r.URL.Query().Get("token")
}
