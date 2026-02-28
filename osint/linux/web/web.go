package main

import (
	"crypto/md5"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"log"
	"mime"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	auth "github.com/abbot/go-http-auth"
	"github.com/alexflint/go-arg"

	"ethanclark.xyz/commander/passgen"
)

type ServeArgs struct {
	Port int    `default:"8000" help:"Port to listen on"`
	Addr string `default:"127.0.0.1" help:"Address to bind to"`
}

type HTTPLogger struct {
	h http.Handler
}

func (l *HTTPLogger) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(os.Stderr, "%5s %s\n", r.Method, r.URL)
	l.h.ServeHTTP(w, r)
}

func GetListScripts(w http.ResponseWriter, r *http.Request) {
	var scripts []Script
	ListScriptWalkFunc := func(path string, info fs.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if info.IsDir() {
			return nil
		}

		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		s := ParseScript(string(raw), path)
		s.Content = ""
		scripts = append(scripts, s)
		return nil
	}

	err := filepath.Walk(config.Scripts, ListScriptWalkFunc)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, "Error listing scripts:\n%s\n", err.Error())
		return
	}

	w.Header().Add("Content-Type", "application/json")
	b, err := json.Marshal(scripts)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, "Error marshalling scripts:\n%s\n", err.Error())
		return
	}
	w.Write(b)
}

func scriptUploadHandler(w http.ResponseWriter, r *http.Request) {
	if strings.Contains(r.URL.Path, "..") {
		w.WriteHeader(http.StatusTeapot)
		fmt.Fprintf(w, "LOUD_INCORRECT_BUZZER.wav\n")
	}
	p := path.Join(config.Scripts, r.URL.Path)
	base := path.Dir(p)
	err := os.MkdirAll(base, os.ModeDir)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, "Upload failed: %s\n", err.Error())
		return
	}
	f, err := os.Create(p)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, "Upload failed: %s\n", err.Error())
		return
	}
	n, err := io.Copy(f, r.Body)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, "Upload failed: %s\n", err.Error())
	} else {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "Script uploaded: %d bytes written\n", n)
	}
}

func outputHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(os.Stderr, "Path: %s\n", r.URL.Path)
	if r.URL.Path == "" {
		m := make(map[string][]string)
		dirs, err := os.ReadDir(config.Output)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprintf(w, "Unable to list output directory: %s\n", err.Error())
			return
		}
		for _, dir := range dirs {
			if !dir.IsDir() {
				continue
			}
			casts, err := filepath.Glob(path.Join(config.Output, dir.Name()) + "/*.cast")
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				fmt.Fprintf(w, "Unable to list cast directory '%s': %s\n", dir.Name(), err.Error())
				return
			}
			// m[dir.Name()] = casts
			for _, cast := range casts {
				m[dir.Name()] = append(m[dir.Name()], cast[len(config.Output)+len(dir.Name())+2:])
			}
		}
		j, err := json.Marshal(m)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprintf(w, "Unable to marshall output: %s\n", err.Error())
			return
		}

		w.Header().Add("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write(j)
	} else {
		http.ServeFileFS(w, r, os.DirFS(config.Output), r.URL.Path)
	}
}

func newJobHandler(dbHandler *DBHandler) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		dbPasswords := make(map[string]string)
		var sshArgs SSHArgs

		// Read request body
		body, err := io.ReadAll(r.Body)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprintf(w, "Error Reading body: %s\n", err.Error())
			return
		}

		// Unmarshal body to args
		err = json.Unmarshal(body, &sshArgs)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprintf(w, "Error parsing body: %s\n", err.Error())
			return
		}

		// Prepare database listener and creds
		dbListener := NewMultiListener()
		defer dbListener.Close()

		// Auth
		authenticator := auth.NewDigestAuthenticator(
			"Script Database",
			MapSecretProvider("Script Database", dbPasswords, md5.New),
		)

		// Run the command
		err = RunSSHCmdArgs(sshArgs, authenticator.Wrap(WrapAuthHandler(dbHandler)), dbPasswords)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprintf(w, "Error running scripts: %s\n", err.Error())
			return
		}

		// Close the listener
		// err = s.Close()
		// if err != nil {
		// 	w.WriteHeader(http.StatusInternalServerError)
		// 	fmt.Fprintf(w, "Error closing db listener: %s\n", err.Error())
		// 	return
		// }

		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "Success\n")
	}
}

func configHandler(w http.ResponseWriter, _ *http.Request) {
	j, err := json.Marshal(config)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, "Error marshalling JSON: %s\n", j)
	}
	w.Header().Add("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(j)
}

func passgenHandler(w http.ResponseWriter, r *http.Request) {
	decoder := json.NewDecoder(r.Body)
	var secrets []string
	err := decoder.Decode(&secrets)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, "Invalid request body: %s\n", err.Error())
	}

	var generated []string
	for _, secret := range secrets {
		generated = append(generated, passgen.GeneratePassword([]byte(secret), config.Passgen))
	}

	j, err := json.Marshal(generated)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, "Error generating passwords: %s\n", err.Error())
	}

	w.Header().Add("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(j)
}

func ServeWeb(parser *arg.Parser) {
	// mime types
	mime.AddExtensionType(".js", "application/javascript")
	mime.AddExtensionType(".css", "text/css")
	mime.AddExtensionType(".html", "text/html")

	// authenticator := auth.NewDigestAuthenticator(
	// 	"Commander Web UI", // Exposing information?
	// 	auth.HtdigestFileProvider(config.HTDigest),
	// )

	servemux := http.NewServeMux()

	// Static files
	servemux.Handle("GET /www/",
		http.StripPrefix(
			"/www/",
			http.FileServerFS(os.DirFS("www")),
		),
	)

	// Scripts
	servemux.HandleFunc("GET /scripts/{$}", GetListScripts)
	servemux.Handle("GET /scripts/",
		http.StripPrefix(
			"/scripts/",
			http.FileServerFS(os.DirFS(config.Scripts)),
		),
	)
	servemux.Handle("POST /scripts/",
		http.StripPrefix(
			"/scripts/",
			http.HandlerFunc(scriptUploadHandler),
		),
	)

	// Output
	servemux.Handle("GET /output/",
		http.StripPrefix(
			"/output/",
			http.HandlerFunc(outputHandler),
		),
	)

	// Config endpoint
	servemux.HandleFunc("GET /config/", configHandler)

	// Config endpoint
	servemux.HandleFunc("POST /passgen/", passgenHandler)

	// Open Database
	db, err := sql.Open("sqlite3", config.Database)
	if err != nil {
		log.Fatalf("Unable to open database: %s\n", err.Error())
	}
	defer db.Close()
	dbHandler := &DBHandler{DB: db}
	servemux.Handle("/db", dbHandler)

	// Job listener
	servemux.HandleFunc("POST /ssh", newJobHandler(dbHandler))

	// Index Redirect
	servemux.Handle("/", http.RedirectHandler("/www/script.html", http.StatusMovedPermanently))

	// servemux.HandleFunc("/db", authenticator.Wrap(handler))
	s := &http.Server{
		// Handler:        authenticator.Wrap(WrapAuthHandler(servemux)),
		Handler:        &HTTPLogger{h: servemux},
		Addr:           fmt.Sprintf("%s:%d", args.ServeArgs.Addr, args.ServeArgs.Port),
		ReadTimeout:    10 * time.Second,
		WriteTimeout:   10 * time.Second,
		MaxHeaderBytes: 1 << 20,
	}
	log.Fatal(s.ListenAndServe())
}