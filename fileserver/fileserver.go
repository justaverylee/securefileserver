package fileserver

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"sort"
	"strconv"
	"strings"

	"github.com/zggz/securefileserver/auth"
)

type fileHandler struct {
	accounts             *auth.Auth
	dataDir              string
	truncateLongRequests bool
	maxBodySize          int64
}

type weightedHashString struct {
	hash   string
	weight float64
}

func parseHashQVal(hashQVal string) weightedHashString {
	s := strings.SplitN(strings.Trim(hashQVal, " "), ";", 2)
	if len(s) == 2 {
		n, err := strconv.ParseFloat(strings.TrimPrefix(s[1], "q="), 64)
		if err != nil {
			n = 1.0
		}
		return weightedHashString{s[0], n}
	}
	return weightedHashString{s[0], 1.0}
}

func insertHash(w http.ResponseWriter, r *http.Request, diskPath string) {
	if header := r.Header.Get("Want-Digest"); header != "" {
		// split by the comma leaving a set of (hash[;q=###])
		hashList := strings.Split(header, ",")
		wantedHashes := make([]weightedHashString, len(hashList))
		// split by the semicolon giving hash and q-value
		for i, e := range hashList {
			wantedHashes[i] = parseHashQVal(e)
		}
		// sort decreasing by q-value
		sort.Slice(wantedHashes, func(i, j int) bool { return wantedHashes[i].weight > wantedHashes[j].weight })
		// create priority sorted list of hashes
		for i, e := range wantedHashes {
			hashList[i] = e.hash
		}

		// getting hashes and setting
		hash, err := getHashes(diskPath, hashList)
		if err == nil {
			w.Header().Set("Digest", hash)
		}
	}
}

func uploadHandler(w http.ResponseWriter, r *http.Request, diskPath string) {
	if patherr := os.MkdirAll(path.Dir(diskPath), os.ModePerm); patherr != nil {
		fmt.Print("The following error occured while trying to make the path for " + diskPath + ": ")
		fmt.Println(patherr)
		http.Error(w, "Could not create required directories", 500)
		return
	}

	f, createerr := os.Create(diskPath)
	if createerr != nil {
		fmt.Print("The following error occured while trying to create the file " + diskPath + ": ")
		fmt.Println(createerr)
		http.Error(w, "File Create Error", 500)
		return
	}
	defer f.Close()

	if _, writeerr := io.Copy(f, r.Body); writeerr != nil {
		fmt.Print("The following error occured while writing to the file " + diskPath + ": ")
		fmt.Println(writeerr)
		http.Error(w, "Write Error", 500)
		return
	}
}

func requestAuth(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", "Basic")
	w.WriteHeader(401)
	w.Write([]byte("Unauthorised.\n"))
}

func (h fileHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	fmt.Printf("Request %s to %s with %d bytes of data from %s\n", r.Method, r.URL.Path, r.ContentLength, r.RemoteAddr)
	relativePath := r.URL.Path
	diskPath := path.Clean(h.dataDir + relativePath)

	if h.truncateLongRequests {
		r.Body = http.MaxBytesReader(w, r.Body, h.maxBodySize)
	} else if r.ContentLength > h.maxBodySize {
		http.Error(w, "Request Body Too Large", 413)
		fmt.Printf("Rejecting Oversized body of size %d from %s\n", r.ContentLength, r.RemoteAddr)
		return
	}

	username, password, ok := r.BasicAuth()
	var user auth.Account
	var err error
	if ok {
		user, err = h.accounts.GetAccount(username, []byte(password))
	}

	if err != nil {
		user = h.accounts.GetDefault()
	}

	if !user.CanRead(relativePath) {
		requestAuth(w)
		return
	}

	switch r.Method {
	case "":
		fallthrough
	case http.MethodGet:
		fallthrough
	case http.MethodHead:
		insertHash(w, r, diskPath)
		http.ServeFile(w, r, diskPath)
	case http.MethodPut:
		if user.CanWrite(relativePath) {
			uploadHandler(w, r, diskPath)
			insertHash(w, r, diskPath)
		} else {
			requestAuth(w)
		}
		// w.WriteHeader(204) // TODO: return 204 (200?) or 201
	case http.MethodOptions:
		w.Header().Set("Accept", strings.Join([]string{http.MethodGet, http.MethodHead, http.MethodPut, http.MethodDelete, http.MethodOptions}, ", "))
		w.WriteHeader(204)
	case http.MethodDelete:
		fallthrough
	default:
		http.Error(w, "Method Not Supported", 405)
	}
}

// MakeRequestHandler creates a request handler with all the configured options on how to respond to requests
// The handler should handle everything including checking authentication internally
func MakeRequestHandler(accounts *auth.Auth, dataDir string, maxBodySize int64, truncateLongRequests bool) http.Handler {
	return fileHandler{accounts: accounts, dataDir: dataDir, truncateLongRequests: truncateLongRequests, maxBodySize: maxBodySize}
}
