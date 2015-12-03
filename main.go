package main

import (
	"fmt"
	"github.com/rs/xhandler"
	log "github.com/sirupsen/logrus"
	"net/http"
	"os"
	"runtime"
	"strconv"
)

const (
	serviceID         = "CLAWIO_OCWEBDAV"
	authServerEnvar   = serviceID + "_AUTH"
	dataServerEnvar   = serviceID + "_DATA"
	metaServerEnvar   = serviceID + "_META"
	portEnvar         = serviceID + "_PORT"
	tmpDirEnvar       = serviceID + "_TMPDIR"
	sharedSecretEnvar = "CLAWIO_SHAREDSECRET"

	endPoint = "/"
)

type environ struct {
	authServer   string
	dataServer   string
	metaServer   string
	port         int
	tmpDir       string
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
	e.tmpDir = os.Getenv(tmpDirEnvar)
	return e, nil
}

func main() {
	runtime.GOMAXPROCS(runtime.NumCPU())
	env, err := getEnviron()
	if err != nil {
		log.Error(err)
		os.Exit(1)
	}

	log.Infof("%s=%s", tmpDirEnvar, env.tmpDir)
	log.Infof("%s=%s", authServerEnvar, env.authServer)
	log.Infof("%s=%s", dataServerEnvar, env.dataServer)
	log.Infof("%s=%s", metaServerEnvar, env.metaServer)
	log.Infof("%s=%d\n", portEnvar, env.port)
	log.Infof("%s=%s\n", sharedSecretEnvar, "******")

	p := &newServerParams{}
	p.authServer = env.authServer
	p.dataServer = env.dataServer
	p.metaServer = env.metaServer
	p.sharedSecret = env.sharedSecret
	p.tmpDir = env.tmpDir

	srv, err := newServer(p)
	if err != nil {
		log.Error(err)
		os.Exit(1)
	}

	c := xhandler.Chain{}
	c.UseC(xhandler.CloseHandler)

	http.Handle(endPoint, c.Handler(srv))
	log.Error(http.ListenAndServe(fmt.Sprintf(":%d", env.port), nil))
}
