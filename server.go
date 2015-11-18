package main

import (
	authlib "github.com/clawio/service.auth/lib"
	metapb "github.com/clawio/service.localstore.meta/proto"
	log "github.com/sirupsen/logrus"
	"golang.org/x/net/context"
	"net/http"
	"strings"
)

const (
	dirPerm = 0755
)

type newServerParams struct {
	authServer   string
	dataServer   string
	metaServer   string
	prop         string
	sharedSecret string
}

func newServer(p *newServerParams) (*server, error) {

	s := &server{}
	s.p = p

	return s, nil
}

type server struct {
	p *newServerParams
}

func (s *server) ServeHTTPC(ctx context.Context, w http.ResponseWriter, r *http.Request) {

	if strings.ToUpper(r.Method) == "PROPFIND" {
		s.authHandler(ctx, w, r, s.propfind)
	} else if strings.ToUpper(r.Method) == "GET" {
		s.authHandler(ctx, w, r, s.get)
	} else {
		w.WriteHeader(http.StatusNotFound)
		return
	}
}

func (s *server) propfind(ctx context.Context, w http.ResponseWriter, r *http.Request) {

	var children bool
	depth := r.Header.Get("Depth")
	// TODO(labkode) Check default for infinity header
	if depth == "1" {
		children = true
	}

	in := &metapb.StatReq{}
	in.AccessToken = authlib.MustFromTokenContext(ctx)
	in.Children = children
	in.Path = getPathFromReq(r)

	con, err := getConnection(s.p.metaServer)
	if err != nil {
		log.Error(err)
		http.Error(w, "", http.StatusInternalServerError)
		return
	}

	client := metapb.NewLocalClient(con)

	meta, err := client.Stat(ctx, in)
	if err != nil {
		// TODO(labkode) Switch grpc error codes for correct HTTP codes
		log.Error(err)
		http.Error(w, "", http.StatusInternalServerError)
		return
	}

	xml, err := metaToXML(meta)
	if err != nil {
		log.Error(err)
		http.Error(w, "", http.StatusInternalServerError)
		return
	}

	w.Header().Set("DAV", "1, 3, extended-mkcol")
	w.Header().Set("ETag", meta.Etag)
	w.Header().Set("Content-Type", "application/xml; charset=utf-8")
	w.WriteHeader(207)

	w.Write(xml)
}

func (s *server) get(ctx context.Context, w http.ResponseWriter, r *http.Request) {

}

// authHandler validates the access token sent in the Cookie or if not present sends
// a the Basic Auth params to the auth service to authenticate the request.
func (s *server) authHandler(ctx context.Context, w http.ResponseWriter, r *http.Request,
	next func(ctx context.Context, w http.ResponseWriter, r *http.Request)) {

	idt, err := s.getIdentityFromReq(r)
	if err != nil {
		// TODO(labkode) add call to auth service with Basic Auth params if found
		//log.Error(err)
		http.Error(w, "", http.StatusUnauthorized)
		return
	}

	ctx = authlib.NewContext(ctx, idt)
	ctx = authlib.NewTokenContext(ctx, s.getTokenFromReq(r))
	next(ctx, w, r)
}

func (s *server) getTokenFromReq(r *http.Request) string {

	var token string

	// Look for cookie - Just for OwnCloud
	authCookie, err := r.Cookie("SESSID")
	if err == nil {
		return authCookie.Value
	}

	// Look for an Authorization header
	if ah := r.Header.Get("Authorization"); ah != "" {
		// Should be a bearer token
		if len(ah) > 6 && strings.ToUpper(ah[0:6]) == "BEARER" {
			token = ah[7:]
		}
	}

	if token == "" {
		// Look for "auth_token" parameter
		r.ParseMultipartForm(10e6)
		if tokStr := r.Form.Get("access_token"); tokStr != "" {
			token = tokStr
		}
	}

	return token
}

func (s *server) getIdentityFromReq(r *http.Request) (*authlib.Identity, error) {
	return authlib.ParseToken(s.getTokenFromReq(r), s.p.sharedSecret)
}
