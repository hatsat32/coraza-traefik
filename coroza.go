package corazatraefik

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/types"
)

type Config struct {
	Include    string `yaml:"include"`
	Directives string `yaml:"include"`
}

func CreateConfig() *Config {
	return &Config{}
}

type CorozaTraefik struct {
	next http.Handler
	waf  coraza.WAF
}

func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	var corozaconfig = coraza.NewWAFConfig()
	var corozawaf, err = coraza.NewWAF(corozaconfig)

	if err != nil {
		fmt.Println(err)
	}

	return &CorozaTraefik{
		next: next,
		waf:  corozawaf,
	}, nil
}

func (ct *CorozaTraefik) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	tx := ct.waf.NewTransaction()

	defer func() {
		tx.ProcessLogging()
		tx.Close()
	}()

	it, err := processRequest(tx, req)

	if it != nil || err != nil {
		errorPage(rw, tx)
		return
	}

	// rw = NewHTTPResponseInterceptor(rw, tx)

	ct.next.ServeHTTP(rw, req)
}

func errorPage(rw http.ResponseWriter, tx types.Transaction) {
	//TODO write som error page
	rw.WriteHeader(403)
	rw.Write([]byte("Access Denied!"))
}

// processRequest fills all transaction variables from an http.Request object
// Most implementations of Coraza will probably use http.Request objects
// so this will implement all phase 0, 1 and 2 variables
// Note: This function will stop after an interruption
// Note: Do not manually fill any request variables
func processRequest(tx types.Transaction, req *http.Request) (*types.Interruption, error) {
	var (
		client string
		cport  int
	)
	// IMPORTANT: Some http.Request.RemoteAddr implementations will not contain port or contain IPV6: [2001:db8::1]:8080
	idx := strings.LastIndexByte(req.RemoteAddr, ':')
	if idx != -1 {
		client = req.RemoteAddr[:idx]
		cport, _ = strconv.Atoi(req.RemoteAddr[idx+1:])
	}

	var in *types.Interruption
	// There is no socket access in the request object, so we neither know the server client nor port.
	tx.ProcessConnection(client, cport, "", 0)
	tx.ProcessURI(req.URL.String(), req.Method, req.Proto)
	for k, vr := range req.Header {
		for _, v := range vr {
			tx.AddRequestHeader(k, v)
		}
	}

	// Host will always be removed from req.Headers() and promoted to the
	// Request.Host field, so we manually add it
	if req.Host != "" {
		tx.AddRequestHeader("Host", req.Host)
		// This connector relies on the host header (now host field) to populate ServerName
		tx.SetServerName(req.Host)
	}

	// Transfer-Encoding header is removed by go/http
	// We manually add it to make rules relying on it work (E.g. CRS rule 920171)
	if req.TransferEncoding != nil {
		tx.AddRequestHeader("Transfer-Encoding", req.TransferEncoding[0])
	}

	in = tx.ProcessRequestHeaders()
	if in != nil {
		return in, nil
	}

	if tx.IsRequestBodyAccessible() {
		// We only do body buffering if the transaction requires request
		// body inspection, otherwise we just let the request follow its
		// regular flow.
		if req.Body != nil && req.Body != http.NoBody {
			it, _, err := tx.ReadRequestBodyFrom(req.Body)
			if err != nil {
				return nil, fmt.Errorf("failed to append request body: %s", err.Error())
			}

			if it != nil {
				return it, nil
			}

			rbr, err := tx.RequestBodyReader()
			if err != nil {
				return nil, fmt.Errorf("failed to get the request body: %s", err.Error())
			}

			// Adds all remaining bytes beyond the coraza limit to its buffer
			// It happens when the partial body has been processed and it did not trigger an interruption
			body := io.MultiReader(rbr, req.Body)
			// req.Body is transparently reinizialied with a new io.ReadCloser.
			// The http handler will be able to read it.
			// Prior to Go 1.19 NopCloser does not implement WriterTo if the reader implements it.
			// - https://github.com/golang/go/issues/51566
			// - https://tip.golang.org/doc/go1.19#minor_library_changes
			// This avoid errors like "failed to process request: malformed chunked encoding" when
			// using io.Copy.
			// In Go 1.19 we just do `req.Body = io.NopCloser(reader)`
			if rwt, ok := body.(io.WriterTo); ok {
				req.Body = struct {
					io.Reader
					io.WriterTo
					io.Closer
				}{body, rwt, req.Body}
			} else {
				req.Body = struct {
					io.Reader
					io.Closer
				}{body, req.Body}
			}
		}
	}

	return tx.ProcessRequestBody()
}
