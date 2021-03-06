# rwtxt-crypt

rwtxt-crypt is a version of the [rwtxt](https://github.com/schollz/rwtxt) CMS that adds
[SQLite encryption](https://github.com/cretz/go-sqleet) and [Tor support](https://github.com/cretz/bine).

**[Download the Latest Release](https://github.com/cretz/rwtxt-crypt/releases)** 

It is built as a single, self-contained executable that can be downloaded via
[releases](https://github.com/cretz/rwtxt-crypt/releases). For Windows, just run the executable (you may have to
click past a Windows warning). For Linux, `chmod +x` the file to make it executable before running. For macOS there is
not a precompiled version yet so please see the build instructions.

## Caveats

* This is an early proof of concept. Bugs/feedback welcome
* Only run the downloaded/built executable on your computer if you trust it and me
* There are no guarantees about the security of the SQLite DB or the Tor implementation/usage

## Usage

Here is the output of running the executable with `--help`:

    Usage of rwtxt-crypt.exe:
      -db string
            name of the database (default "rwtxt-crypt.db")
      -dbPass string
            string password to encrypt DB, default dbPassFile or prompt
      -dbPassFile string
            file with string password to encrypt DB, default dbPass or prompt
      -debug
            debug mode
      -onionKeyFile string
            file to load/save PEM onion private key to, default new each time
      -torDataDir string
            path to tor data dir, default temp dir in local folder deleted on close
      -torPath string
            path to tor executable, default use embedded version

Simply executing with no parameters will prompt for a password for the DB, run with the embedded Tor version, create/use
the DB in the current directory, create the Tor data directory in the current directory (and delete on close), and
create a new v3 onion service address each time.

**NOTE: Creating an onion service can take a minute.**

## Building

To build:

* Make a note of `GOPATH` env var (manually set or the default in more recent Go versions as `~/go`) and make sure its
  `bin` dir is on the `PATH`
* Fetch it - run `go get github.com/cretz/rwtxt-crypt` (this will give `rwtxt` errors, that's ok)
* Make `rwtxt` - navigate to `$GOPATH/src/github.com/schollz/rwtxt` and run `make` (must do in MinGW on Windows)
* Remove explicit `sqlite` dep - navigate to `$GOPATH/src/github.com/schollz/sqlite3dump` and remove or comment out the
  `_ "github.com/mattn/go-sqlite3"` line (see [this issue](https://github.com/schollz/sqlite3dump/issues/1))
* Build tor statically - navigate to `$GOPATH/src/github.com/cretz/tor-static`, checkout the `tor-0.3.5.x` branch, and
  follow the instructions in the README to build a statically-linkable version of Tor.
* Build the executable - navigate to `$GOPATH/src/github.com/cretz/rwtxt-crypt` and run `go build`
