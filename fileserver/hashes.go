package fileserver

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"hash"
	"io"
	"os"
	"strings"
)

// Source: https://mrwaggel.be/post/generate-md5-hash-of-a-file-in-golang/
func hashFile(f *os.File, h hash.Hash, name string) (string, error) {
	var returnString string

	if _, err := io.Copy(h, f); err != nil {
		return returnString, err
	}

	hashInBytes := h.Sum(nil)

	returnString = hex.EncodeToString(hashInBytes)

	return name + "=" + returnString, nil
}

// GetHashes gets the hash of a file given an array of in order prefered hash types
// will return the hash as [hashtype]=[hash] where hashtype is the first supported
// type in the wantDigest array. If no types are supported, an md5 hash is returned
func getHashes(filePath string, wantDigest []string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	for _, d := range wantDigest {
		switch strings.ToLower(d) {
		case "md5":
			return hashFile(file, md5.New(), d)
		case "sha":
			fallthrough
		case "sha-1":
			return hashFile(file, sha1.New(), d)
		case "sha-256":
			return hashFile(file, sha256.New(), d)
		case "sha-512":
			return hashFile(file, sha512.New(), d)
		}
	}
	return hashFile(file, md5.New(), "MD5")
}
