// Command idpserver serves the test OpenID Connect provider over TLS for the
// MONGODB-OIDC integration test (test/oidc). Test-only control endpoints
// change the signed-in user and the token lifetime and end browser sessions.
package main

import (
	"encoding/json"
	"flag"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/krishnamanaiducloud/mongo-portal/internal/testidp"
)

func main() {
	addr := flag.String("addr", ":8443", "listen address")
	cert := flag.String("cert", "", "TLS certificate")
	key := flag.String("key", "", "TLS key")
	issuer := flag.String("issuer", "https://idp:8443", "issuer URL")
	client := flag.String("client", "mongo-portal-test", "client id")
	audience := flag.String("audience", "mongodb-test", "access token audience")
	flag.Parse()

	idp := testidp.New(*issuer, *client)
	idp.AccessAudience, idp.AnyClient = *audience, true
	mux := http.NewServeMux()
	mux.Handle("/", idp.Handler())
	mux.HandleFunc("POST /test/user", func(w http.ResponseWriter, r *http.Request) {
		idp.User = testidp.User{Subject: r.URL.Query().Get("sub"), Name: r.URL.Query().Get("sub")}
	})
	mux.HandleFunc("POST /test/ttl", func(w http.ResponseWriter, r *http.Request) {
		s, _ := strconv.Atoi(r.URL.Query().Get("seconds"))
		idp.TokenTTL = time.Duration(s) * time.Second
	})
	mux.HandleFunc("POST /test/end-sessions", func(w http.ResponseWriter, r *http.Request) {
		idp.EndSessions()
	})
	mux.HandleFunc("GET /test/stats", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]int{"issued": idp.Issued, "refreshed": idp.Refreshed, "interactive": idp.Interactive})
	})
	srv := &http.Server{Addr: *addr, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	log.Printf("test idp listening on %s (issuer %s)", *addr, *issuer)
	log.Fatal(srv.ListenAndServeTLS(*cert, *key))
}
