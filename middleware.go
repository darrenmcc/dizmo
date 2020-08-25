package dizmo

import (
	"net/http"
	"strings"
)

// CORSHandler is a middleware func for setting all headers that enable CORS.
// If an originSuffix is provided, a strings.HasSuffix check will be performed
// before adding any CORS header. If an empty string is provided, any Origin
// header found will be placed into the CORS header. If no Origin header is
// found, no headers will be added.
func CORSHandler(f http.Handler, originSuffix string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin != "" &&
			(originSuffix == "" || strings.HasSuffix(origin, originSuffix)) {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Credentials", "true")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, x-requested-by, *")
			w.Header().Set("Access-Control-Allow-Methods", "GET, PUT, POST, PATCH, DELETE, OPTIONS")

			if r.Method == http.MethodOptions {
				w.WriteHeader(http.StatusOK)
				return
			}
		}
		f.ServeHTTP(w, r)
	})
}

// NoCacheHandler is a middleware func for setting the Cache-Control to no-cache.
func NoCacheHandler(f http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
		w.Header().Set("Pragma", "no-cache")
		w.Header().Set("Expires", "0")
		f.ServeHTTP(w, r)
	})
}
