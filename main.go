package main

import (
	"flag"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/zggz/securefileserver/pkg/auth"
	"github.com/zggz/securefileserver/pkg/fileserver"
	"github.com/zggz/securefileserver/pkg/https"
)

func main() {
	authfile := flag.String("auth", "", "(Required) Auth configuration location. Make sure this isn't in the data directory")
	certs := flag.String("cert", "certs", "Where to cache SSL certificates on disk")
	datapath := flag.String("data", "", "(Required) Data directory to serve and store from")
	host := flag.String("host", "", "Hostname of this server which we will request certificate for. Required if tls")
	maxBodySize := flag.Int64("maxbody", 1<<30, "Maximum size of file uploads")
	tls := flag.Bool("tls", false, "If true use TLS with certificate. Default is to run on http only")
	flag.Parse()

	if *tls && *host == "" {
		flag.PrintDefaults()
		os.Exit(1)
	}

	if *datapath == "" {
		flag.PrintDefaults()
		os.Exit(1)
	}

	accountsstore, storeerror := auth.MakeGoCacheStore(*authfile)
	if storeerror != nil {
		fmt.Print("Error creating auth store: ")
		fmt.Println(storeerror)
		os.Exit(2)
	}
	authdb := auth.MakeAuthFromStore(accountsstore)

	https.StartServer(*tls, *certs, *host, "", "", fileserver.MakeRequestHandler(authdb, *datapath, *maxBodySize, true), &http.Server{
		ReadHeaderTimeout: 30 * time.Second,
		ReadTimeout:       70 * time.Second,
		WriteTimeout:      10 * time.Second,
		MaxHeaderBytes:    1 << 20,
		//ErrorLog:          errLog,
	})
}
