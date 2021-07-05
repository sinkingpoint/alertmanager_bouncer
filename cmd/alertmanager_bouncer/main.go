package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/sinkingpoint/alertmanager_bouncer/lib/bouncer"
	johari "github.com/sinkingpoint/johari-go/lib"
	"gopkg.in/alecthomas/kingpin.v2"
)

type config struct {
	backendURL            *url.URL
	listenURL             *net.TCPAddr
	dialTimeout           time.Duration
	tlsHandshakeTimeout   time.Duration
	responseHeaderTimeout time.Duration
	serverReadTimeout     time.Duration
	serverWriteTimeout    time.Duration
	tlsCertFile           string
	tlsKeyFile            string
	bouncersConfigFile    string
}

func loadBouncersFromFile(conf config) ([]bouncer.Bouncer, error) {
	jsonFile, err := os.Open(conf.bouncersConfigFile)
	defer jsonFile.Close()
	if err != nil {
		return nil, err
	}

	bytes, err := ioutil.ReadAll(jsonFile)
	if err != nil {
		return nil, err
	}

	return bouncer.ParseBouncers(bytes)
}

func main() {
	config := config{}
	johari.InitTracing(johari.JohariConfig{
		ServiceName:  "alertmanager-bouncer",
		CollectorURL: "http://jaeger:14268/api/traces",
		SamplingRate: 1,
	})

	app := kingpin.New("alertmanager_bouncer", "A Business Logic Reverse Proxy for Alertmanager")
	app.Flag("backend.addr", "The URL of the backend to upstream to").Required().URLVar(&config.backendURL)
	app.Flag("listen.addr", "The URL for the reverse proxy to listen on").Required().TCPVar(&config.listenURL)
	app.Flag("config.bouncersfile", "The file containing the list of bouncers to create").Required().ExistingFileVar(&config.bouncersConfigFile)
	app.Flag("timeout.dial", "The timeout of the initial connection to the backend").Default("30s").DurationVar(&config.dialTimeout)
	app.Flag("timeout.tlshandshake", "The timeout of the TLS handshake to the backend, after a connection is established").Default("10s").DurationVar(&config.tlsHandshakeTimeout)
	app.Flag("timeout.responseheader", "The timeout of the receive of the initial headers from the backend").Default("10s").DurationVar(&config.responseHeaderTimeout)
	app.Flag("timeout.serverread", "The timeout of the reverse proxy to read requests").Default("5s").DurationVar(&config.serverReadTimeout)
	app.Flag("timeout.serverwrite", "The timeout of the reverse proxy to write the response to the upstream client").Default("10s").DurationVar(&config.serverWriteTimeout)
	app.Flag("tls.certfile", "The file path of the TLS cert file on disk, if you want to serve TLS").ExistingFileVar(&config.tlsCertFile)
	app.Flag("tls.keyfile", "The file path of the TLS key file on disk, if you want to serve TLS").ExistingFileVar(&config.tlsKeyFile)
	kingpin.MustParse(app.Parse(os.Args[1:]))

	var err error
	bouncers, err := loadBouncersFromFile(config)
	if err != nil {
		log.Panicf("Failed to parse bouncers from %s: %s", config.bouncersConfigFile, err.Error())
	}

	fmt.Printf("Loaded %d bouncers\n", len(bouncers))

	proxy := bouncer.NewBouncingReverseProxy(config.backendURL, bouncers, nil)
	server := http.Server{
		ReadTimeout:  config.serverReadTimeout,
		WriteTimeout: config.serverWriteTimeout,
		Handler:      johari.NewHTTPServerWrapper(proxy),
		Addr:         config.listenURL.String(),
	}

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGHUP)
	go func() {
		for {
			<-sigChan
			log.Printf("Received a SIGHUP. Reloading Bouncers from %s", config.bouncersConfigFile)
			bouncers, err := loadBouncersFromFile(config)
			if err != nil {
				log.Printf("Failed to parse bouncers from %s: %s. Aboring Reload.", config.bouncersConfigFile, err.Error())
			}

			bouncer.SetBouncers(bouncers, proxy)
		}
	}()

	if config.tlsCertFile != "" && config.tlsKeyFile != "" {
		err = server.ListenAndServeTLS(config.tlsCertFile, config.tlsKeyFile)
	} else {
		if config.tlsCertFile != "" {
			log.Fatalln("TLS Cert file given without TLS Key File. Bailing.")
		} else if config.tlsKeyFile != "" {
			log.Fatalln("TLS Key file given without TLS Config File. Bailing.")
		}
		err = server.ListenAndServe()
	}

	if err != nil {
		log.Fatalf("Got an error while serving HTTP: %s\n", err.Error())
	}
}
