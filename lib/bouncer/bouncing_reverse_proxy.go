package bouncer

import (
	"bytes"
	"context"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"regexp"
	"strings"

	johari "github.com/sinkingpoint/johari-go/lib"
	"go.opentelemetry.io/otel/attribute"
	"gopkg.in/yaml.v2"
)

type deciderSerialized struct {
	Name   string            `yaml:"name"`
	Config map[string]string `yaml:"config"`
}

type bouncerSerialized struct {
	Method   string              `yaml:"method"`
	URIRegex string              `yaml:"uriRegex"`
	Deciders []deciderSerialized `yaml:"deciders"`
	DryRun   bool                `yaml:"dryrun"`
}

// ParseBouncers loads a slice of Bouncers from a given byte array
// which should represent a YAML encoded text stream of serialized bouncers.
func ParseBouncers(bytes []byte) ([]Bouncer, error) {
	InitDeciderTemplates()
	var serializedBouncers struct {
		Bouncers []bouncerSerialized `yaml:"bouncers"`
	}
	err := yaml.Unmarshal(bytes, &serializedBouncers)
	if err != nil {
		return nil, err
	}

	bouncers := make([]Bouncer, len(serializedBouncers.Bouncers))
	for bouncerIndex, serializedBouncer := range serializedBouncers.Bouncers {
		uriRegex, err := regexp.Compile(serializedBouncer.URIRegex)
		if err != nil {
			return nil, err
		}

		target := Target{
			Method:   serializedBouncer.Method,
			URIRegex: uriRegex,
		}

		deciders := make([]Decider, len(serializedBouncer.Deciders))
		for deciderIndex, serializedDecider := range serializedBouncer.Deciders {
			if _, exists := deciderTemplates[serializedDecider.Name]; !exists {
				return nil, fmt.Errorf("No decider template named %s found", serializedDecider.Name)
			}

			for _, expected := range deciderTemplates[serializedDecider.Name].requiredConfigVars {
				if _, exists := serializedDecider.Config[expected]; !exists {
					return nil, fmt.Errorf("Expected config variable %s not found for %s", expected, serializedDecider.Name)
				}
			}

			deciders[deciderIndex] = deciderTemplates[serializedDecider.Name].templateFunc(serializedDecider.Config)
		}

		bouncers[bouncerIndex] = Bouncer{
			Target:   target,
			Deciders: deciders,
			DryRun:   serializedBouncer.DryRun,
		}
	}

	return bouncers, nil
}

// Target Represents a potential target for an HTTP request
// with both a Method (Which represents the HTTP method), and a URI Regex
// which matches the URI of the request
type Target struct {
	Method   string
	URIRegex *regexp.Regexp
}

// Matches returns whether the given the given Target matches the given
// request, i.e. the method matches, and the URI matches the regex
func (t Target) Matches(req *http.Request) bool {
	methodMatches := strings.EqualFold(req.Method, t.Method)
	uriMatches := t.URIRegex.MatchString(req.URL.RequestURI())
	return methodMatches && uriMatches
}

// HTTPError represents an error, coupled with an HTTP Status Code
type HTTPError struct {
	Status int
	Err    error
}

// ToResponse converts the given HTTPError into an HTTP Response,
// which can be sent back to a client
func (h *HTTPError) ToResponse() *http.Response {
	return &http.Response{
		StatusCode: h.Status,
		Body:       ioutil.NopCloser(bytes.NewBufferString(h.Err.Error())),
	}
}

// Decider is a function which takes an HTTP request and optionally returns
// an HTTPError, if the given request should be rejected
type Decider func(req *http.Request, context context.Context) *HTTPError

// Bouncer is a coupling of a Target, and a number of deciders. It can optionally
// "Bounce" a request, i.e. reject it based on a series of Deciders
type Bouncer struct {
	Target   Target
	Deciders []Decider
	DryRun   bool
}

// Bounce takes an HTTPRequest and optionally returns an HTTPError
// if the request should be "Bounced", i.e. rejected.
func (b Bouncer) Bounce(req *http.Request) *HTTPError {
	if !b.Target.Matches(req) {
		return nil
	}

	bctx, bspan := johari.NewChildSpan(req.Context(), "bouncer")
	defer bspan.End()

	bspan.SetAttributes(attribute.String("target_method", b.Target.Method))
	bspan.SetAttributes(attribute.String("target_regex", b.Target.URIRegex.String()))
	bspan.SetAttributes(attribute.Bool("dry_run", b.DryRun))

	// We want multiple deciders to be able to read the body, so
	// we have to read it here, and then reload it into a buffer for every decider
	var rawBody []byte
	var err error
	if req.Body == nil || req.Body == http.NoBody {
		rawBody = []byte{}
	} else {
		defer req.Body.Close()
		rawBody, err = ioutil.ReadAll(req.Body)
		if err != nil {
			bspan.RecordError(err)
			return &HTTPError{
				Status: 500,
				Err:    fmt.Errorf("Failed to read body from request"),
			}
		}
	}

	for _, decider := range b.Deciders {
		dctx, dspan := johari.NewChildSpan(bctx, "decider")
		defer dspan.End()
		req.Body = ioutil.NopCloser(bytes.NewBuffer(rawBody))
		defer req.Body.Close()
		err := decider(req, dctx)
		if err != nil {
			if b.DryRun {
				log.Printf("Would have rejected %s %s: %s\n", req.Method, req.URL.RequestURI(), err.Err.Error())
			} else {
				log.Printf("Rejected %s %s: %s\n", req.Method, req.URL.RequestURI(), err.Err.Error())
				dspan.AddEvent("decider.rejected")
				return err
			}
		} else {
			dspan.AddEvent("decider.accepted")
		}
	}

	req.Body = ioutil.NopCloser(bytes.NewBuffer(rawBody))
	return nil
}

type bouncingTransport struct {
	backingTransport http.RoundTripper
	bouncers         []Bouncer
}

// SetBouncers sets the set of bouncers on the given proxy
// This allows us to reload a set of bouncers on a running proxy, without
// restarting the process
func SetBouncers(bouncers []Bouncer, proxy *httputil.ReverseProxy) error {
	transport, ok := proxy.Transport.(bouncingTransport)
	if !ok {
		return fmt.Errorf("Given proxy is not a BouncingReverseProxy")
	}

	proxy.Transport = bouncingTransport{
		backingTransport: transport.backingTransport,
		bouncers:         bouncers,
	}

	return nil
}

func (b bouncingTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	for _, bouncer := range b.bouncers {
		err := bouncer.Bounce(request)
		if err != nil {
			return err.ToResponse(), nil
		}
	}
	return b.backingTransport.RoundTrip(request)
}

// NewBouncingReverseProxy generates a ReverseProxy instance which runs the given
// set of bouncers on every request that passes through it
func NewBouncingReverseProxy(backend *url.URL, bouncers []Bouncer, backingTransport http.RoundTripper) *httputil.ReverseProxy {
	if backingTransport == nil {
		backingTransport = http.DefaultTransport
	}
	proxy := httputil.NewSingleHostReverseProxy(backend)
	proxy.Transport = bouncingTransport{
		backingTransport: backingTransport,
		bouncers:         bouncers,
	}

	return proxy
}
