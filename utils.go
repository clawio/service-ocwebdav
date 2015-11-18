package main

import (
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"net/http"
	"path"
)

func getPathFromReq(r *http.Request) string {
	return path.Clean(r.URL.Path)
}

func getConnection(addr string) (*grpc.ClientConn, error) {
	con, err := grpc.Dial(addr, grpc.WithInsecure())
	if err != nil {
		log.Error(err)
		return nil, err
	}

	log.Infof("created connection to %s", addr)
	return con, nil
}
