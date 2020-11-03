package https

import (
	"fmt"
	"net/http"
	"time"

	"golang.org/x/crypto/acme/autocert"
)

func redirectToHTTPS(w http.ResponseWriter, r *http.Request) {
	location := "https://" + r.Host + r.RequestURI
	w.Header().Add("Location", location)
	w.Header().Add("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusMovedPermanently)
	w.Write([]byte("This site requires https. <a href=\"" + location + "\">Click here</a>."))
}

// StartServer creates a server using the passed arguments. baseServer can be nil
func StartServer(useTLS bool, certDir string, host string, httpAddr string, httpsAddr string, handler http.Handler, baseServer *http.Server) {
	if baseServer == nil {
		baseServer = &http.Server{}
	}

	baseServer.Handler = handler

	if useTLS {
		certManager := &autocert.Manager{
			Cache:      autocert.DirCache(certDir),
			Prompt:     autocert.AcceptTOS,
			HostPolicy: autocert.HostWhitelist(host),
		}

		baseServer.Addr = httpsAddr
		baseServer.TLSConfig = certManager.TLSConfig()

		redirectServer := &http.Server{
			Addr:         httpAddr,
			Handler:      certManager.HTTPHandler(http.HandlerFunc(redirectToHTTPS)),
			ReadTimeout:  5 * time.Second,
			WriteTimeout: 5 * time.Second,
		}

		fmt.Println("Starting redirect server on address " + httpAddr)
		go redirectServer.ListenAndServe()

		fmt.Println("Starting https server on address " + httpsAddr)
		fmt.Println(baseServer.ListenAndServeTLS("", ""))
	} else {
		baseServer.Addr = httpAddr

		fmt.Println("Starting http server on address " + httpAddr)
		fmt.Println(baseServer.ListenAndServe())
	}
}
