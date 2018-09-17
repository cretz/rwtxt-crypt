package main

import (
	"bytes"
	"database/sql"
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"syscall"

	log "github.com/cihub/seelog"
	"github.com/cretz/bine/tor"
	"github.com/cretz/bine/torutil/ed25519"
	_ "github.com/cretz/go-sqleet/sqlite3"
	"github.com/schollz/rwtxt"
	"github.com/schollz/rwtxt/pkg/db"
	"golang.org/x/crypto/ssh/terminal"
)

func main() {
	defer log.Flush()
	if err := run(); err != nil {
		log.Errorf("Failure: %v", err)
		os.Exit(1)
	}
}

func run() error {
	// Parse flags
	debug := flag.Bool("debug", false, "debug mode")
	dbName := flag.String("db", "rwtxt.db", "name of the database")
	dbPass := flag.String("dbPass", "", "string password to encrypt DB")
	dbPassFile := flag.String("dbPassFile", "", "file with string password to encrypt DB")
	onionKeyFile := flag.String("onionKeyFile", "", "file to load/save PEM onion private key to")
	flag.Parse()
	if flag.NArg() > 0 {
		return fmt.Errorf("Unrecognized args: %v", flag.Args())
	}

	// Set the log level
	if *debug {
		db.SetLogLevel("debug")
	} else {
		db.SetLogLevel("info")
	}

	// Obtain the DB key
	log.Debug("Getting key for DB")
	dbKey, err := getDBKey(*dbPass, *dbPassFile)
	if err != nil {
		return fmt.Errorf("Failed getting DB key: %v", err)
	}

	// Create the FS
	log.Debugf("Creating/opening DB at %v", *dbName)
	fs, err := createFileSystem(*dbName, dbKey)
	if err != nil {
		return fmt.Errorf("Failed opening DB at %v: %v", *dbName, err)
	}
	defer fs.Close()

	// Start Tor
	log.Debug("Starting Tor")
	tor, err := startTor(*debug)
	if err != nil {
		return fmt.Errorf("Unable to start Tor: %v", err)
	}
	defer tor.Close()

	// Listen on onion
	log.Debug("Creating onion service")
	onion, err := listenOnion(tor, *onionKeyFile)
	if err != nil {
		return fmt.Errorf("Unable to create onion service: %v", err)
	}
	defer onion.Close()

	// Serve rwtxt
	log.Debug("Serving rwtxt over HTTP")
	rwt, err := rwtxt.New(fs)
	if err != nil {
		return fmt.Errorf("Failed creating rwtxt instance: %v", err)
	}
	log.Infof("Open Tor browser and visit rwtxt at http://%v.onion", onion.ID)
	return http.Serve(onion, http.HandlerFunc(rwt.Handler))
}

type logDebugWriter struct{}

func (logDebugWriter) Write(p []byte) (n int, err error) {
	log.Debug(string(p))
	return
}

// getDBKey returns the given pass if non-empty, or the pass from the file if
// non-empty, or prompts the user for it.
func getDBKey(maybeDBPass string, maybeDBPassFile string) (string, error) {
	if maybeDBPass != "" {
		return maybeDBPass, nil
	}
	if maybeDBPassFile != "" {
		log.Debugf("Loading DB pass from file at %v", maybeDBPassFile)
		if dbPassFileBytes, err := ioutil.ReadFile(maybeDBPassFile); err != nil {
			return "", fmt.Errorf("Failed loading %v: %v", maybeDBPassFile, err)
		} else if len(dbPassFileBytes) == 0 {
			return "", fmt.Errorf("DB pass file empty at %v", maybeDBPassFile)
		} else {
			return string(dbPassFileBytes), nil
		}
	}
	// No key or file means password prompt
	for {
		fmt.Print("Enter DB password: ")
		if dbPassBytes, err := terminal.ReadPassword(int(syscall.Stdin)); err != nil {
			return "", fmt.Errorf("Failed reading password: %v", err)
		} else if len(dbPassBytes) > 0 {
			return string(dbPassBytes), nil
		}
		log.Info("Empty password not allowed")
	}
}

func createFileSystem(dbPath string, dbKey string) (fs *db.FileSystem, err error) {
	if fs = (&db.FileSystem{Name: dbPath}); fs.Name == "" {
		return nil, fmt.Errorf("DB path cannot be empty")
	} else if fs.DB, err = sql.Open("sqleet", fs.Name+"?_key="+url.QueryEscape(dbKey)); err != nil {
		return nil, err
	} else if err = fs.InitializeDB(false); err != nil {
		// OK not closing DB here on failure
		return nil, err
	}
	return
}

func startTor(debug bool) (*tor.Tor, error) {
	startConf := &tor.StartConf{}
	if debug {
		startConf.DebugWriter = logDebugWriter{}
	}
	return tor.Start(nil, startConf)
}

// listenOnion accepts empty keyFile which means ephemeral service is created.
// If keyFile does not exist, it is written with the created key.
func listenOnion(t *tor.Tor, keyFile string) (*tor.OnionService, error) {
	// Use v3 onion service, listen on port 80 remotely and random port locally
	listenConf := &tor.ListenConf{RemotePorts: []int{80}, Version3: true}
	// Load key from file if able
	keyFileNotExist := false
	if keyFile != "" {
		if onionKeyPEMBytes, err := ioutil.ReadFile(keyFile); os.IsNotExist(err) {
			keyFileNotExist = true
		} else if err != nil {
			return nil, fmt.Errorf("Unable to load key file at %v: %v", keyFile, err)
		} else if block, rest := pem.Decode(onionKeyPEMBytes); block == nil {
			return nil, fmt.Errorf("Invalid PEM block in key file %v", keyFile)
		} else if len(bytes.TrimSpace(rest)) != 0 {
			return nil, fmt.Errorf("Expecting only one PEM key in file %v", keyFile)
		} else if len(block.Bytes) != ed25519.PrivateKeySize {
			return nil, fmt.Errorf("Invalid key size in file %v", keyFile)
		} else {
			listenConf.Key = ed25519.PrivateKey(block.Bytes)
		}
	}
	// Start the listen, then store key back in file if needed
	onion, err := t.Listen(nil, listenConf)
	if err != nil {
		return nil, err
	}
	if keyFileNotExist {
		// We don't have to close the onion in here, it's closed when Tor is on error
		block := &pem.Block{
			Type:  "RWTXT-CRYPT PRIVATE KEY",
			Bytes: onion.Key.(ed25519.KeyPair).PrivateKey(),
		}
		file, err := os.OpenFile(keyFile, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			return nil, fmt.Errorf("Unable to create file at %v: %v", keyFile, err)
		}
		defer file.Close()
		if err = pem.Encode(file, block); err != nil {
			return nil, fmt.Errorf("Unable to write key at %v: %v", keyFile, err)
		}
	}
	return onion, nil
}
