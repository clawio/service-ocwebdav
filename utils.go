package main

import (
	"code.google.com/p/go-uuid/uuid"
	"fmt"
	authlib "github.com/clawio/service-auth/lib"
	metapb "github.com/clawio/service-ocwebdav/proto/metadata"
	log "github.com/sirupsen/logrus"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	metadata "google.golang.org/grpc/metadata"
	"net/http"
	"path"
	"regexp"
	"strconv"
	"strings"
)

func getMeta(ctx context.Context, addr, p string, children bool) (*metapb.Metadata, error) {

	in := &metapb.StatReq{}
	in.AccessToken = authlib.MustFromTokenContext(ctx)
	in.Children = children
	in.Path = p

	con, err := getConnection(addr)
	if err != nil {
		return nil, err
	}

	defer con.Close()

	client := metapb.NewMetaClient(con)

	meta, err := client.Stat(ctx, in)
	if err != nil {
		return nil, err
	}

	return meta, nil
}

func getIdentityFromReq(r *http.Request, secret string) (*authlib.Identity, error) {
	return authlib.ParseToken(getTokenFromReq(r), secret)
}

func getPathFromReq(r *http.Request) string {
	return path.Join("/", strings.TrimPrefix(r.URL.Path, remoteURL))
}

func getConnection(addr string) (*grpc.ClientConn, error) {
	con, err := grpc.Dial(addr, grpc.WithInsecure())
	if err != nil {
		return nil, err
	}
	return con, nil
}

// getTraceID returns the traceID that comes in the request
// or generate a new one
func getTraceID(r *http.Request) string {
	traceID := r.Header.Get("CIO-TraceID")
	if traceID == "" {
		return uuid.New()
	}
	return traceID
}

// The key type is unexported to prevent collisions with context keys defined in
// other packages.
type key int

// logKey is the context key for an identity.  Its value of zero is
// arbitrary.  If this package defined other context keys, they would have
// different integer values.
const logKey key = 0

// NewLogContext returns a new Context carrying a logger.
func NewLogContext(ctx context.Context, logger *log.Entry) context.Context {
	return context.WithValue(ctx, logKey, logger)
}

// MustFromLogContext extracts the logger from ctx.
// If not present it panics.
func MustFromLogContext(ctx context.Context) *log.Entry {
	val, ok := ctx.Value(logKey).(*log.Entry)
	if !ok {
		panic("logger is not registered")
	}
	return val
}

func getTokenFromReq(r *http.Request) string {

	var token string

	// Look for cookie - Just for OwnCloud
	authCookie, err := r.Cookie("OC_SessionPassphrase")
	if err == nil && authCookie.Value != "" {
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

func newGRPCTraceContext(ctx context.Context, trace string) context.Context {
	md := metadata.Pairs("trace", trace)
	ctx = metadata.NewContext(ctx, md)
	return ctx
}

func getGRPCTraceID(ctx context.Context) string {

	md, ok := metadata.FromContext(ctx)
	if !ok {
		return uuid.New()
	}

	tokens := md["trace"]
	if len(tokens) == 0 {
		return uuid.New()
	}

	if tokens[0] != "" {
		return tokens[0]
	}

	return uuid.New()
}

type chunkPathInfo struct {
	ResourcePath string
	TransferID   string
	TotalChunks  uint64
	CurrentChunk uint64
}

func (c *chunkPathInfo) UploadID() string {
	return "chunking-" + c.TransferID + "-" + strconv.FormatUint(c.TotalChunks, 10)
}

type chunkHeaderInfo struct {
	// OC-Chunked = 1
	OCChunked bool

	// OC-Chunk-Size
	OCChunkSize uint64

	// OC-Total-Length
	OCTotalLength uint64
}

func (c *chunkPathInfo) String() string {
	return fmt.Sprintf("< path:%s total_chunks:%d current_chunk:%d id:%s >", c.ResourcePath, c.TotalChunks, c.CurrentChunk, c.TransferID)
}

// IsChunked determines if an upload is chunked or not.
func isChunked(p string) (bool, error) {
	return regexp.MatchString(`-chunking-\w+-[0-9]+-[0-9]+$`, p)
}

// GetChunkPathInfo obtains the different parts of a chunk from the path.
func getChunkPathInfo(p string) (*chunkPathInfo, error) {
	parts := strings.Split(p, "-chunking-")
	tail := strings.Split(parts[1], "-")

	totalChunks, err := strconv.ParseUint(tail[1], 10, 64)
	if err != nil {
		return nil, err
	}
	currentChunk, err := strconv.ParseUint(tail[2], 10, 64)
	if err != nil {
		return nil, err
	}

	if currentChunk >= totalChunks {
		return nil, fmt.Errorf("current chunk:%d exceeds total chunks:%d.", currentChunk, totalChunks)
	}

	info := &chunkPathInfo{}
	info.ResourcePath = parts[0]
	info.TransferID = tail[0]
	info.TotalChunks = totalChunks
	info.CurrentChunk = currentChunk

	return info, nil
}
