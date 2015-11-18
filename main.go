package main

import (
	"fmt"
	"github.com/rs/xhandler"
	"log"
	"net/http"
	"os"
	"strconv"
)

const (
	serviceID         = "CLAWIO_OCWEBDAV"
	authServerEnvar   = serviceID + "_AUTH"
	dataServerEnvar   = serviceID + "_DATA"
	metaServerEnvar   = serviceID + "_META"
	portEnvar         = serviceID + "_PORT"
	sharedSecretEnvar = "CLAWIO_SHAREDSECRET"

	endPoint = "/"
)

type environ struct {
	authServer   string
	dataServer   string
	metaServer   string
	port         int
	sharedSecret string
}

func getEnviron() (*environ, error) {
	e := &environ{}
	port, err := strconv.Atoi(os.Getenv(portEnvar))
	if err != nil {
		return nil, err
	}
	e.port = port
	e.sharedSecret = os.Getenv(sharedSecretEnvar)
	e.authServer = os.Getenv(authServerEnvar)
	e.dataServer = os.Getenv(dataServerEnvar)
	e.metaServer = os.Getenv(metaServerEnvar)
	return e, nil
}

func printEnviron(e *environ) {
	log.Printf("%s=%s", authServerEnvar, e.authServer)
	log.Printf("%s=%s", dataServerEnvar, e.dataServer)
	log.Printf("%s=%s", metaServerEnvar, e.metaServer)
	log.Printf("%s=%d\n", portEnvar, e.port)
	log.Printf("%s=%s\n", sharedSecretEnvar, "******")
}

func main() {

	log.Printf("Service %s started", serviceID)

	env, err := getEnviron()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	printEnviron(env)
	p := &newServerParams{}
	p.authServer = env.authServer
	p.dataServer = env.dataServer
	p.metaServer = env.metaServer
	p.sharedSecret = env.sharedSecret

	srv, err := newServer(p)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	c := xhandler.Chain{}
	c.UseC(xhandler.CloseHandler)

	http.Handle(endPoint, c.Handler(srv))
	fmt.Fprintln(os.Stderr, http.ListenAndServe(fmt.Sprintf(":%d", env.port), nil))
}
