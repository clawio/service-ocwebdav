package main

import (
	"encoding/json"
	"fmt"
	authlib "github.com/clawio/service-auth/lib"
	authpb "github.com/clawio/service-ocwebdav/proto/auth"
	metapb "github.com/clawio/service-ocwebdav/proto/metadata"
	log "github.com/sirupsen/logrus"
	"github.com/zenazn/goji/web/mutil"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"path"
	"strconv"
	"strings"
	"time"
)

const (
	dirPerm = 0755
)

var (
	statusURL       = path.Join(endPoint, "/status.php")
	remoteURL       = path.Join(endPoint, "/remote.php/webdav")
	capabilitiesURL = path.Join(endPoint, "/ocs/v1.php/cloud/capabilities")
)

type newServerParams struct {
	authServer   string
	dataServer   string
	metaServer   string
	prop         string
	sharedSecret string
	tmpDir       string
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
	// Force server to close connection
	r.Close = true

	traceID := getTraceID(r)
	reqLogger := log.WithField("trace", traceID).WithField("svc", serviceID)
	ctx = NewLogContext(ctx, reqLogger)
	ctx = newGRPCTraceContext(ctx, traceID)

	reqLogger.Info("request started")

	// Time request
	reqStart := time.Now()

	// Sniff the status and content size for logging
	lw := mutil.WrapWriter(w)

	defer func() {
		// Compute request duration
		reqDur := time.Since(reqStart)

		// Log access info
		reqLogger.WithFields(log.Fields{
			"method":      r.Method,
			"type":        "access",
			"status_code": lw.Status(),
			"duration":    reqDur.Seconds(),
			"size":        lw.BytesWritten(),
		}).Infof("%s %s %03d", r.Method, r.URL.String(), lw.Status())

		reqLogger.Info("request finished")

	}()

	if strings.HasPrefix(r.URL.Path, statusURL) && strings.ToUpper(r.Method) == "GET" {
		reqLogger.WithField("op", "status").Info()
		s.status(ctx, lw, r)
	} else if strings.HasPrefix(r.URL.Path, capabilitiesURL) && strings.ToUpper(r.Method) == "GET" {
		reqLogger.WithField("op", "capabilities").Info()
		s.capabilities(ctx, lw, r)
	} else if strings.HasPrefix(r.URL.Path, remoteURL) && strings.ToUpper(r.Method) == "HEAD" {
		reqLogger.WithField("op", "head").Info()
		s.authHandler(ctx, lw, r, s.head)
	} else if strings.HasPrefix(r.URL.Path, remoteURL) && strings.ToUpper(r.Method) == "PROPFIND" {
		reqLogger.WithField("op", "propfind").Info()
		s.authHandler(ctx, lw, r, s.propfind)
	} else if strings.HasPrefix(r.URL.Path, remoteURL) && strings.ToUpper(r.Method) == "GET" {
		reqLogger.WithField("op", "get").Info()
		s.authHandler(ctx, lw, r, s.get)
	} else if strings.HasPrefix(r.URL.Path, remoteURL) && strings.ToUpper(r.Method) == "PUT" {
		reqLogger.WithField("op", "put").Info()
		p := getPathFromReq(r)
		chunked, err := isChunked(p)
		if err != nil {
			reqLogger.Error(err)
			http.Error(w, "", http.StatusInternalServerError)
			return
		}

		if chunked {
			reqLogger.Info("upload is chunked")
			s.authHandler(ctx, lw, r, s.putChunked)
			return
		}

		s.authHandler(ctx, lw, r, s.put)
	} else if strings.HasPrefix(r.URL.Path, remoteURL) && strings.ToUpper(r.Method) == "LOCK" {
		reqLogger.WithField("op", "lock").Info()
		s.authHandler(ctx, lw, r, s.lock)
	} else if strings.HasPrefix(r.URL.Path, remoteURL) && strings.ToUpper(r.Method) == "OPTIONS" {
		reqLogger.WithField("op", "options").Info()
		s.authHandler(ctx, lw, r, s.options)
	} else if strings.HasPrefix(r.URL.Path, remoteURL) && strings.ToUpper(r.Method) == "MKCOL" {
		reqLogger.WithField("op", "mkcol").Info()
		s.authHandler(ctx, lw, r, s.mkcol)
	} else if strings.HasPrefix(r.URL.Path, remoteURL) && strings.ToUpper(r.Method) == "MKCOL" {
		reqLogger.WithField("op", "proppatch").Info()
		s.authHandler(ctx, lw, r, s.proppatch)
	} else if strings.HasPrefix(r.URL.Path, remoteURL) && strings.ToUpper(r.Method) == "COPY" {
		reqLogger.WithField("op", "copy").Info()
		s.authHandler(ctx, lw, r, s.copy)
	} else if strings.HasPrefix(r.URL.Path, remoteURL) && strings.ToUpper(r.Method) == "MOVE" {
		reqLogger.WithField("op", "move").Info()
		s.authHandler(ctx, lw, r, s.move)
	} else if strings.HasPrefix(r.URL.Path, remoteURL) && strings.ToUpper(r.Method) == "DELETE" {
		reqLogger.WithField("op", "delete").Info()
		s.authHandler(ctx, lw, r, s.delete)
	} else {
		w.WriteHeader(http.StatusNotFound)
		return
	}
}

func (s *server) delete(ctx context.Context, w http.ResponseWriter, r *http.Request) {

	logger := MustFromLogContext(ctx)

	p := getPathFromReq(r)

	logger.Infof("path is %s", p)

	con, err := getConnection(s.p.metaServer)
	if err != nil {
		logger.Error(err)
		http.Error(w, "", http.StatusInternalServerError)
		return
	}

	defer con.Close()

	client := metapb.NewMetaClient(con)

	in := &metapb.RmReq{}
	in.Path = p
	in.AccessToken = authlib.MustFromTokenContext(ctx)

	_, err = client.Rm(ctx, in)
	if err != nil {
		logger.Error(err)

		gErr := grpc.Code(err)
		switch {
		case gErr == codes.PermissionDenied:
			http.Error(w, "", http.StatusForbidden)
			return
		default:
			http.Error(w, "", http.StatusInternalServerError)
			return
		}
	}

	w.WriteHeader(http.StatusNoContent)
}
func (s *server) move(ctx context.Context, w http.ResponseWriter, r *http.Request) {

	logger := MustFromLogContext(ctx)

	src := getPathFromReq(r)
	u, err := url.Parse(r.Header.Get("Destination"))
	if err != nil {
		logger.Error(err)
		http.Error(w, "", http.StatusBadRequest)
		return
	}

	dst := path.Clean(strings.TrimPrefix(u.Path, remoteURL))
	if dst == "" {
		http.Error(w, "", http.StatusBadRequest)
		return
	}

	logger.Infof("src is %s", src)
	logger.Infof("dst is %s", dst)

	con, err := getConnection(s.p.metaServer)
	if err != nil {
		logger.Error(err)
		http.Error(w, "", http.StatusInternalServerError)
		return
	}

	defer con.Close()

	client := metapb.NewMetaClient(con)

	in := &metapb.MvReq{}
	in.Src = src
	in.Dst = dst
	in.AccessToken = authlib.MustFromTokenContext(ctx)

	_, err = client.Mv(ctx, in)
	if err != nil {
		logger.Error(err)

		gErr := grpc.Code(err)
		switch {
		case gErr == codes.PermissionDenied:
			http.Error(w, "", http.StatusForbidden)
			return
		default:
			http.Error(w, "", http.StatusInternalServerError)
			return
		}
	}

	meta, err := getMeta(ctx, s.p.metaServer, dst, false)
	if err != nil {
		logger.Error(err)

		gErr := grpc.Code(err)
		switch {
		case gErr == codes.NotFound:
			http.Error(w, "", http.StatusNotFound)
			return
		case gErr == codes.PermissionDenied:
			http.Error(w, "", http.StatusForbidden)
			return
		default:
			http.Error(w, "", http.StatusInternalServerError)
			return
		}
	}

	w.Header().Set("ETag", meta.Etag)
	w.Header().Set("OC-FileId", meta.Id)
	w.Header().Set("OC-ETag", meta.Etag)
	t := time.Unix(int64(meta.Modified), 0)
	lastModifiedString := t.Format(time.RFC1123)
	w.Header().Set("Last-Modified", lastModifiedString)

	// TODO(labkode) is resource existed (overwrite the code should be 204)
	w.WriteHeader(http.StatusCreated)
}

func (s *server) copy(ctx context.Context, w http.ResponseWriter, r *http.Request) {

	logger := MustFromLogContext(ctx)

	src := getPathFromReq(r)
	u, err := url.Parse(r.Header.Get("Destination"))
	if err != nil {
		logger.Error(err)
		http.Error(w, "", http.StatusBadRequest)
		return
	}

	dst := path.Clean(strings.TrimPrefix(u.Path, remoteURL))
	if dst == "" {
		http.Error(w, "", http.StatusBadRequest)
		return
	}

	logger.Infof("src is %s", src)
	logger.Infof("dst is %s", dst)

	con, err := getConnection(s.p.metaServer)
	if err != nil {
		logger.Error(err)
		http.Error(w, "", http.StatusInternalServerError)
		return
	}

	defer con.Close()

	client := metapb.NewMetaClient(con)

	in := &metapb.CpReq{}
	in.Src = src
	in.Dst = dst
	in.AccessToken = authlib.MustFromTokenContext(ctx)

	_, err = client.Cp(ctx, in)
	if err != nil {
		logger.Error(err)

		gErr := grpc.Code(err)
		switch {
		case gErr == codes.PermissionDenied:
			http.Error(w, "", http.StatusForbidden)
			return
		default:
			http.Error(w, "", http.StatusInternalServerError)
			return
		}
	}

	w.WriteHeader(http.StatusNoContent)
}

func (s *server) proppatch(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	return
}
func (s *server) mkcol(ctx context.Context, w http.ResponseWriter, r *http.Request) {

	logger := MustFromLogContext(ctx)

	p := getPathFromReq(r)

	logger.Infof("path is %s", p)

	con, err := getConnection(s.p.metaServer)
	if err != nil {
		logger.Error(err)
		http.Error(w, "", http.StatusInternalServerError)
		return
	}

	defer con.Close()

	client := metapb.NewMetaClient(con)

	in := &metapb.MkdirReq{}
	in.AccessToken = authlib.MustFromTokenContext(ctx)
	in.Path = p

	_, err = client.Mkdir(ctx, in)
	if err != nil {
		logger.Error(err)

		gErr := grpc.Code(err)
		switch {
		case gErr == codes.PermissionDenied:
			http.Error(w, "", http.StatusForbidden)
			return
		default:
			http.Error(w, "", http.StatusInternalServerError)
			return
		}
	}

	w.WriteHeader(http.StatusCreated)
}

func (s *server) capabilities(ctx context.Context, w http.ResponseWriter, r *http.Request) {

	capabilities := `
	{
	  "ocs": {
	    "data": {
	      "capabilities": {
	        "core": {
	          "pollinterval": 60
	        },
	        "files": {
	          "bigfilechunking": true,
	          "undelete": true,
	          "versioning": true
	        }
	      },
	      "version": {
	        "edition": "",
	        "major": 8,
	        "micro": 1,
	        "minor": 2,
	        "string": "8.2.1"
	      }
	    },
	    "meta": {
	      "message": null,
	      "status": "ok",
	      "statuscode": 100
	    }
	  }
	}`

	w.Header().Add("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(capabilities))
}

func (s *server) status(ctx context.Context, w http.ResponseWriter, r *http.Request) {

	logger := MustFromLogContext(ctx)

	major := "8"
	minor := "2"
	micro := "1"
	edition := ""

	version := fmt.Sprintf("%s.%s.%s.4", major, minor, micro)
	versionString := fmt.Sprintf("%s.%s.%s", major, minor, micro)

	status := &struct {
		Installed     bool   `json:"installed"`
		Maintenace    bool   `json:"maintenance"`
		Version       string `json:"version"`
		VersionString string `json:"versionstring"`
		Edition       string `json:"edition"`
	}{
		true,
		false,
		version,
		versionString,
		edition,
	}

	statusJSON, err := json.MarshalIndent(status, "", "    ")
	if err != nil {
		logger.Error(err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	w.Header().Add("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(statusJSON)
}

func (s *server) head(ctx context.Context, w http.ResponseWriter, r *http.Request) {

	logger := MustFromLogContext(ctx).WithField("op", "head")

	p := getPathFromReq(r)

	logger.Info("path is %s", p)

	meta, err := getMeta(ctx, s.p.metaServer, p, false)
	if err != nil {
		logger.Error(err)

		gErr := grpc.Code(err)
		switch {
		case gErr == codes.NotFound:
			http.Error(w, "", http.StatusNotFound)
			return
		case gErr == codes.PermissionDenied:
			http.Error(w, "", http.StatusForbidden)
			return
		default:
			http.Error(w, "", http.StatusInternalServerError)
			return
		}
	}

	logger.Debugf("meta is %s", meta)

	w.Header().Set("Content-Type", meta.MimeType)
	w.Header().Set("ETag", meta.Etag)
	w.Header().Set("OC-FileId", meta.Id)
	w.Header().Set("OC-ETag", meta.Etag)
	t := time.Unix(int64(meta.Modified), 0)
	lastModifiedString := t.Format(time.RFC1123)
	w.Header().Set("Last-Modified", lastModifiedString)
}

func (s *server) lock(ctx context.Context, w http.ResponseWriter, r *http.Request) {

	logger := MustFromLogContext(ctx).WithField("op", "lock")

	p := getPathFromReq(r)

	logger.Infof("path is %s", p)

	xml := `<?xml version="1.0" encoding="utf-8"?>
	<prop xmlns="DAV:">
		<lockdiscovery>
			<activelock>
				<allprop/>
				<timeout>Second-604800</timeout>
				<depth>Infinity</depth>
				<locktoken>
				<href>opaquelocktoken:00000000-0000-0000-0000-000000000000</href>
				</locktoken>
			</activelock>
		</lockdiscovery>
	</prop>`

	w.Header().Set("Content-Type", "text/xml; charset=\"utf-8\"")
	w.Header().Set("Lock-Token",
		"opaquelocktoken:00000000-0000-0000-0000-000000000000")
	w.Write([]byte(xml))
}

func (s *server) propfind(ctx context.Context, w http.ResponseWriter, r *http.Request) {

	logger := MustFromLogContext(ctx)

	var children bool
	depth := r.Header.Get("Depth")
	// TODO(labkode) Check default for infinity header
	if depth == "1" {
		children = true
	}

	p := getPathFromReq(r)

	logger.Infof("path is %s", p)

	meta, err := getMeta(ctx, s.p.metaServer, p, children)
	if err != nil {
		logger.Error(err)

		gErr := grpc.Code(err)
		switch {
		case gErr == codes.NotFound:
			http.Error(w, "", http.StatusNotFound)
			return
		case gErr == codes.PermissionDenied:
			http.Error(w, "", http.StatusForbidden)
			return
		default:
			http.Error(w, "", http.StatusInternalServerError)
			return
		}
	}

	logger.Debugf("meta is %s", meta)

	xml, err := metaToXML(meta)
	if err != nil {
		logger.Error(err)
		http.Error(w, "", http.StatusInternalServerError)
		return
	}

	w.Header().Set("DAV", "1, 3, extended-mkcol")
	w.Header().Set("Content-Type", "application/xml; charset=utf-8")
	w.WriteHeader(207)

	w.Write(xml)
}

func (s *server) get(ctx context.Context, w http.ResponseWriter, r *http.Request) {

	logger := MustFromLogContext(ctx)

	p := getPathFromReq(r)

	logger.Infof("path is %s", p)

	meta, err := getMeta(ctx, s.p.metaServer, p, false)
	if err != nil {
		logger.Error(err)

		gErr := grpc.Code(err)
		switch {
		case gErr == codes.NotFound:
			http.Error(w, "", http.StatusNotFound)
			return
		case gErr == codes.PermissionDenied:
			http.Error(w, "", http.StatusForbidden)
			return
		default:
			http.Error(w, "", http.StatusInternalServerError)
			return
		}
	}

	logger.Debugf("meta is %s", meta)

	c := &http.Client{}
	req, err := http.NewRequest("GET", s.p.dataServer+p, nil)
	if err != nil {
		logger.Error(err)
		http.Error(w, "", http.StatusInternalServerError)
		return
	}

	req.Header.Add("Authorization", "Bearer "+authlib.MustFromTokenContext(ctx))
	req.Header.Add("CIO-TraceID", logger.Data["trace"].(string))

	res, err := c.Do(req)
	if err != nil {
		logger.Error(err)
		http.Error(w, "", http.StatusInternalServerError)
		return
	}

	defer res.Body.Close()

	if res.StatusCode != 200 {
		http.Error(w, "", res.StatusCode)
		return
	}

	w.Header().Set("Content-Type", meta.MimeType)
	w.Header().Set("ETag", meta.Etag)
	w.Header().Set("OC-FileId", meta.Id)
	w.Header().Set("OC-ETag", meta.Etag)
	t := time.Unix(int64(meta.Modified), 0)
	lastModifiedString := t.Format(time.RFC1123)
	w.Header().Set("Last-Modified", lastModifiedString)

	logger.Infof("file checksum is %s", meta.Checksum)
	if meta.Checksum != "" {
		w.Header().Set("OC-Checksum", meta.Checksum)
	}

	io.Copy(w, res.Body)
}

func (s *server) put(ctx context.Context, w http.ResponseWriter, r *http.Request) {

	logger := MustFromLogContext(ctx)

	p := getPathFromReq(r)

	logger.Infof("path is %s", p)

	// if client sends etag check against the current value
	// if file is not found or etags do not match return 412
	ifMatchHeader := r.Header.Get("If-Match")
	if ifMatchHeader != "" {

		meta, err := getMeta(ctx, s.p.metaServer, p, false)
		if err != nil {
			logger.Error(err)
			http.Error(w, "", http.StatusPreconditionFailed)
			return
		}

		// TODO(labkode) refactor this
		if ifMatchHeader != `"`+meta.Etag+`"` {
			logger.Warnf("etags do not match. client send %s and server has %s", ifMatchHeader, meta.Etag)
			http.Error(w, "", http.StatusPreconditionFailed)
			return
		}

	}

	c := &http.Client{}
	req, err := http.NewRequest("PUT", s.p.dataServer+path.Join("/", p), r.Body)
	if err != nil {
		logger.Error(err)
		http.Error(w, "", http.StatusInternalServerError)
		return
	}

	req.Close = true
	req.Header.Add("Authorization", "Bearer "+authlib.MustFromTokenContext(ctx))
	req.Header.Add("CIO-Checksum", r.Header.Get("OC-Checksum"))
	req.Header.Add("CIO-TraceID", logger.Data["trace"].(string))

	res, err := c.Do(req)
	if err != nil {
		logger.Error(err)
		http.Error(w, "", http.StatusInternalServerError)
		return
	}

	defer res.Body.Close()

	if res.StatusCode != 201 {
		w.WriteHeader(res.StatusCode)
		return
	}

	meta, err := getMeta(ctx, s.p.metaServer, p, false)
	if err != nil {
		logger.Error(err)

		gErr := grpc.Code(err)
		switch {
		case gErr == codes.NotFound:
			http.Error(w, "", http.StatusNotFound)
			return
		case gErr == codes.PermissionDenied:
			http.Error(w, "", http.StatusForbidden)
			return
		default:
			http.Error(w, "", http.StatusInternalServerError)
			return
		}
	}

	w.Header().Set("ETag", meta.Etag)
	w.Header().Set("OC-FileId", meta.Id)
	w.Header().Set("OC-ETag", meta.Etag)
	t := time.Unix(int64(meta.Modified), 0)
	lastModifiedString := t.Format(time.RFC1123)
	w.Header().Set("Last-Modified", lastModifiedString)
	w.Header().Set("X-OC-MTime", "accepted")

	w.WriteHeader(http.StatusCreated)

}

func (s *server) putChunked(ctx context.Context, w http.ResponseWriter, r *http.Request) {

	logger := MustFromLogContext(ctx)

	p := getPathFromReq(r)

	logger.Infof("path is %s", p)

	chunkInfo, err := getChunkPathInfo(p)
	if err != nil {
		logger.Error(err)
		http.Error(w, "", http.StatusInternalServerError)
		return
	}

	// if client sends etag check against the current value
	// if file is not found or etags do not match return 412
	ifMatchHeader := r.Header.Get("If-Match")
	if ifMatchHeader != "" {

		meta, err := getMeta(ctx, s.p.metaServer, chunkInfo.ResourcePath, false)
		if err != nil {
			logger.Error(err)
			http.Error(w, "", http.StatusPreconditionFailed)
			return
		}

		// TODO(labkode) refactor this
		if ifMatchHeader != `"`+meta.Etag+`"` {
			logger.Warnf("etags do not match. client send %s and server has %s", ifMatchHeader, meta.Etag)
			http.Error(w, "", http.StatusPreconditionFailed)
			return
		}

	}

	logger.Infof("%s", chunkInfo.String())

	tmpFn, tmpFile, err := s.tmpFile()
	if err != nil {
		logger.Error(err)
		http.Error(w, "", http.StatusInternalServerError)
		return
	}

	logger.Infof("created tmp file %s", tmpFn)

	_, err = io.Copy(tmpFile, r.Body)
	if err != nil {
		logger.Error(err)
		http.Error(w, "", http.StatusInternalServerError)
		return
	}

	logger.Infof("copied r.Body to %s", tmpFn)

	err = tmpFile.Close()
	if err != nil {
		logger.Error(err)
		http.Error(w, "", http.StatusInternalServerError)
		return
	}

	logger.Infof("closed %s", tmpFn)

	chunkFolder, err := s.getChunkFolder(chunkInfo)
	if err != nil {
		logger.Error(err)
		http.Error(w, "", http.StatusInternalServerError)
		return
	}

	logger.Infof("chunk folder is %s", chunkFolder)

	chunkDst := path.Join(chunkFolder, path.Clean(strconv.FormatUint(chunkInfo.CurrentChunk, 10)))

	logger.Infof("chunk path is %s", chunkDst)

	err = os.Rename(tmpFn, chunkDst)
	if err != nil {
		logger.Error(err)
		http.Error(w, "", http.StatusInternalServerError)
		return
	}

	logger.Infof("moved chunk from %s to %s", tmpFn, chunkDst)

	// Check that all chunks are uploaded.
	// This is very inefficient, the server has to check that it has all the
	// chunks after each uploaded chunk.
	// A two-phase upload like DropBox is better, because the server will
	// assembly the chunks when the client asks for it.

	fdChunkFolder, err := os.Open(chunkFolder)
	if err != nil {
		logger.Error(err)
		http.Error(w, "", http.StatusInternalServerError)
		return
	}

	logger.Infof("opened chunk folder %s", chunkFolder)

	defer fdChunkFolder.Close()

	fns, err := fdChunkFolder.Readdirnames(-1)
	if err != nil {
		logger.Error(err)
		http.Error(w, "", http.StatusInternalServerError)
		return
	}

	logger.Infof("there are %d out of %d chunks", len(fns), chunkInfo.TotalChunks)

	if len(fns) < int(chunkInfo.TotalChunks) {
		logger.Infof("chunk upload is not complete")
		w.WriteHeader(http.StatusCreated)
		return
	}

	assemblyFn, assemblyFile, err := s.tmpFile()
	if err != nil {
		logger.Error(err)
		http.Error(w, "", http.StatusInternalServerError)
		return
	}

	logger.Infof("created assembly file at %s", assemblyFn)

	for chunk := 0; chunk < int(chunkInfo.TotalChunks); chunk++ {

		cp := path.Join(chunkFolder,
			strconv.FormatInt(int64(chunk), 10))

		logger.Infof("going to process chunk %d with path %s", chunk, cp)

		fdChunk, err := os.Open(cp)
		if err != nil {
			logger.Error(err)
			http.Error(w, "", http.StatusInternalServerError)
			return
		}

		logger.Infof("opened chunk at %s", cp)

		_, err = io.Copy(assemblyFile, fdChunk)
		if err != nil {
			logger.Error(err)
			http.Error(w, "", http.StatusInternalServerError)
			return
		}

		// close fd now. If we defer it we will have thousands of open fd
		// until assembly process
		err = fdChunk.Close()
		if err != nil {
			logger.Error(err)
			http.Error(w, "", http.StatusInternalServerError)
			return
		}

		logger.Infof("copied chunk %s into assembly file %s", cp, assemblyFn)
	}

	// Point fd to beginning of file to start copying
	_, err = assemblyFile.Seek(0, 0)
	if err != nil {
		logger.Error(err)
		http.Error(w, "", http.StatusInternalServerError)
		return
	}

	logger.Infof("assembly file sought to first offset for copy")

	// TODO(labkode) instead uploading the file when it is assembled the best is to provide
	// a core API like DropBox chunk sessions that is compatible with everyone
	c := &http.Client{}
	req, err := http.NewRequest("PUT", s.p.dataServer+path.Join("/", chunkInfo.ResourcePath), assemblyFile)
	if err != nil {
		logger.Error(err)
		http.Error(w, "", http.StatusInternalServerError)
		return
	}

	req.Close = true
	req.Header.Add("Authorization", "Bearer "+authlib.MustFromTokenContext(ctx))
	req.Header.Add("CIO-Checksum", r.Header.Get("OC-Checksum"))
	req.Header.Add("CIO-TraceID", logger.Data["trace"].(string))

	res, err := c.Do(req)
	if err != nil {
		logger.Error(err)
		http.Error(w, "", http.StatusInternalServerError)
		return
	}

	logger.Infof("assembly file %s uploaded to %s", assemblyFn, s.p.dataServer)

	defer res.Body.Close()

	if res.StatusCode != 201 {
		w.WriteHeader(res.StatusCode)
		return
	}

	meta, err := getMeta(ctx, s.p.metaServer, chunkInfo.ResourcePath, false)
	if err != nil {
		logger.Error(err)

		gErr := grpc.Code(err)
		switch {
		case gErr == codes.NotFound:
			http.Error(w, "", http.StatusNotFound)
			return
		case gErr == codes.PermissionDenied:
			http.Error(w, "", http.StatusForbidden)
			return
		default:
			http.Error(w, "", http.StatusInternalServerError)
			return
		}
	}

	// TODO(labkode) Analyze side effects on not respecting OC-Mtime
	w.Header().Set("ETag", meta.Etag)
	w.Header().Set("OC-FileId", meta.Id)
	w.Header().Set("OC-ETag", meta.Etag)
	t := time.Unix(int64(meta.Modified), 0)
	lastModifiedString := t.Format(time.RFC1123)
	w.Header().Set("Last-Modified", lastModifiedString)
	w.Header().Set("X-OC-MTime", "accepted")

	w.WriteHeader(http.StatusCreated)
}

func (s *server) options(ctx context.Context, w http.ResponseWriter, r *http.Request) {

	logger := MustFromLogContext(ctx)

	p := getPathFromReq(r)

	logger.Infof("path is %s", p)

	meta, err := getMeta(ctx, s.p.metaServer, p, false)
	if err != nil {
		logger.Error(err)

		gErr := grpc.Code(err)
		switch {
		case gErr == codes.NotFound:
			http.Error(w, "", http.StatusNotFound)
			return
		case gErr == codes.PermissionDenied:
			http.Error(w, "", http.StatusForbidden)
			return
		default:
			http.Error(w, "", http.StatusInternalServerError)
			return
		}
	}

	logger.Debugf("meta is %s", meta)

	allow := "OPTIONS, LOCK, GET, HEAD, POST, DELETE, PROPPATCH, COPY,"
	allow += " MOVE, UNLOCK, PROPFIND"
	if !meta.IsContainer {
		allow += ", PUT"

	}

	w.Header().Set("Allow", allow)
	w.Header().Set("DAV", "1, 2")
	w.Header().Set("MS-Author-Via", "DAV")
	//w.Header().Set("Accept-Ranges", "bytes")
	w.WriteHeader(http.StatusOK)
	return
}

// authHandler validates the access token sent in the Cookie or if not present sends
// a the Basic Auth params to the auth service to authenticate the request.
func (s *server) authHandler(ctx context.Context, w http.ResponseWriter, r *http.Request,
	next func(ctx context.Context, w http.ResponseWriter, r *http.Request)) {

	logger := MustFromLogContext(ctx)

	idt, err := getIdentityFromReq(r, s.p.sharedSecret)
	if err == nil {

		logger.Info(idt)

		ctx = authlib.NewContext(ctx, idt)
		ctx = authlib.NewTokenContext(ctx, getTokenFromReq(r))
		next(ctx, w, r)
	} else {
		// Authenticate against auth service
		// if basic credentials are found
		user, pass, ok := r.BasicAuth()
		if !ok {
			logger.Error("no credentials found in request")
			w.Header().Set("WWW-Authenticate", "Basic Realm='ClawIO credentials'")
			http.Error(w, "", http.StatusUnauthorized)
			return
		}

		con, err := getConnection(s.p.authServer)
		if err != nil {
			logger.Error(err)
			http.Error(w, "", http.StatusInternalServerError)
			return
		}

		defer con.Close()

		logger.Infof("connected to %s", s.p.authServer)

		client := authpb.NewAuthClient(con)

		in := &authpb.AuthRequest{}
		in.Username = user
		in.Password = pass

		res, err := client.Authenticate(ctx, in)
		if err != nil {
			logger.Error(err)

			if grpc.Code(err) == codes.Unauthenticated {
				w.Header().Set("WWW-Authenticate", "Basic Realm='ClawIO credentials'")
				http.Error(w, "", http.StatusUnauthorized)
				return
			}

			http.Error(w, "", http.StatusInternalServerError)
			return
		}

		logger.Infof("basic auth successful for username %s", user)
		// TODO(labkode) Set cookie

		idt, err := authlib.ParseToken(res.Token, s.p.sharedSecret)
		if err != nil {
			logger.Error(err)
			http.Error(w, "", http.StatusInternalServerError)
			return
		}

		logger.Info(idt)

		// token added to the request because when proxied
		// no all servers will handle basic auth, but all will handle
		// the access token
		r.Header.Set("Authorization", "Bearer "+res.Token)

		ctx = authlib.NewContext(ctx, idt)
		ctx = authlib.NewTokenContext(ctx, res.Token)
		next(ctx, w, r)
	}
}

func (s *server) tmpFile() (string, *os.File, error) {

	file, err := ioutil.TempFile(s.p.tmpDir, serviceID)
	if err != nil {
		return "", nil, err
	}

	fn := path.Join(path.Clean(file.Name()))

	return fn, file, nil
}

func (s *server) getChunkFolder(i *chunkPathInfo) (string, error) {
	// not using the resource path in the chunk folder name allows uploading
	// to the same folder after a move without having to restart the chunk
	// upload
	p := path.Join(s.p.tmpDir, path.Clean(i.UploadID()))

	if err := os.MkdirAll(p, dirPerm); err != nil {
		return "", err
	}
	return p, nil
}
