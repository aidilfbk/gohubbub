// Copyright 2014 Daniel Pupius

// Package gohubbub provides a PubSubHubbub subscriber client.  It will request
// subscriptions from a hub and handle responses as required by the prootcol.
// Update notifications will be forwarded to the handler function that was
// registered on subscription.
package gohubbub

import (
	"bytes"
	"container/ring"
	"crypto"
	"crypto/hmac"
	"crypto/md5"
	"encoding/base64"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	linkParser "github.com/peterhellberg/link"
)

// Struct for storing information about a subscription.
type subscription struct {
	hub        string
	topic      string
	id         uuid.UUID
	handler    func(string, []byte) // Content-Type, ResponseBody
	lease      time.Duration
	verifiedAt time.Time
}

func (s subscription) String() string {
	return fmt.Sprintf("%s (#%d %s)", s.topic, s.id, s.lease)
}

var nilSubscription = &subscription{}

// A HttpRequester is used to make HTTP requests.  http.Client{} satisfies this
// interface.
type HttpRequester interface {
	Do(req *http.Request) (resp *http.Response, err error)
}

// Client allows you to register a callback for PubSubHubbub subscriptions,
// handlers will be executed when an update is received.
type Client struct {
	// Hostname or IP address and port that remote client will connect to, should
	// be accessible by the hub. e.g. "push.myhost.com:4100"
	self string

	from          string                   // String passed in the "From" header.
	running       bool                     // Whether the server is running.
	subscriptions map[string]*subscription // Map of subscriptions.
	httpRequester HttpRequester            // e.g. http.Client{}.
	history       *ring.Ring               // Stores past messages, for deduplication.
	https         bool                     // Whether the callback url supports HTTPS
	hubSecretKey  *[]byte
}

func NewClient(self string, from string) *Client {
	return &Client{
		self,
		fmt.Sprintf("%s / %s (gohubbub)", from, self),
		false,
		make(map[string]*subscription),
		&http.Client{}, // TODO: Use client with Timeout transport.
		ring.New(50),
		false,
		nil,
	}
}

// SetHubSecretKey sets the hub.secret used in subscriptions
func (client *Client) SetHubSecretKey(key []byte) error {
	enc := base64.RawURLEncoding
	keyLen := enc.EncodedLen(len(key))
	if keyLen > 200 {
		/*
			https://www.w3.org/TR/websub/#subscriber-sends-subscription-request
			This parameter MUST be less than 200 bytes in length.
		*/
		return fmt.Errorf("Secret key too long, %x", key)
	}
	urlSafeKey := make([]byte, keyLen)
	enc.Encode(urlSafeKey, key)
	client.hubSecretKey = &urlSafeKey
	return nil
}

// HasSubscription returns true if a subscription exists for the topic.
func (client *Client) HasSubscription(topic string) bool {
	_, ok := client.subscriptions[topic]
	return ok
}

// Discover queries an RSS or Atom feed for the hub which it is publishing to.
func (client *Client) Discover(topic string) (string, error) {
	req, _ := http.NewRequest("GET", topic, nil)
	req.Header.Add("Accept", "application/rss+xml, application/rdf+xml, application/atom+xml, application/xml;q=0.9, text/xml;q=0.8")

	resp, err := client.httpRequester.Do(req)
	if err != nil {
		return "", fmt.Errorf("unable to fetch feed, %v", err)
	}
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("feed request failed, status code %d", resp.StatusCode)
	}

	defer resp.Body.Close()

	for _, link := range linkParser.ParseResponse(resp) {
		if link.Rel == "hub" {
			return link.URI, nil
		}
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("error reading feed response, %v", err)
	}

	var f feed
	if xmlError := xml.Unmarshal(body, &f); xmlError != nil {
		return "", fmt.Errorf("unable to parse xml, %v", xmlError)
	}

	links := append(f.Link, f.Channel.Link...)
	for _, link := range links {
		if link.Rel == "hub" {
			return link.Href, nil
		}
	}

	return "", fmt.Errorf("no hub found in feed")
}

// DiscoverAndSubscribe queries an RSS or Atom feed for the hub which it is
// publishing to, then subscribes for updates.
func (client *Client) DiscoverAndSubscribe(topic string, handler func(string, []byte)) error {
	hub, err := client.Discover(topic)
	if err != nil {
		return fmt.Errorf("unable to find hub, %v", err)
	}
	client.Subscribe(hub, topic, handler)
	return nil
}

// Subscribe adds a handler will be called when an update notification is
// received.  If a handler already exists for the given topic it will be
// overridden.
func (client *Client) Subscribe(hub, topic string, handler func(string, []byte), leaseSeconds ...uint32) {
	s := &subscription{
		hub:     hub,
		topic:   topic,
		id:      uuid.New(),
		handler: handler,
	}
	if len(leaseSeconds) == 1 {
		s.lease = time.Second * time.Duration(leaseSeconds[0])
	}
	client.subscriptions[topic] = s
	if client.running {
		client.makeSubscriptionRequest(s)
	}
}

// Unsubscribe sends an unsubscribe notification and removes the subscription.
func (client *Client) Unsubscribe(topic string) {
	if s, exists := client.subscriptions[topic]; exists {
		delete(client.subscriptions, topic)
		if client.running {
			client.makeUnsubscribeRequeast(s)
		}
	} else {
		log.Printf("Cannot unsubscribe, %s doesn't exist.", topic)
	}
}

func (client *Client) defaultHTTPHandler(httpMuxArg ...*http.ServeMux) http.Handler {
	var httpMux *http.ServeMux
	if len(httpMuxArg) == 1 {
		httpMux = httpMuxArg[0]
	} else {
		httpMux = http.NewServeMux()
	}

	client.RegisterHandler(httpMux)

	// For default server give other paths a noop endpoint.
	httpMux.HandleFunc("/", handleDefaultRequest)

	return httpMux
}

// StartAndServe starts a server using DefaultServeMux, and makes initial
// subscription requests.
func (client *Client) StartAndServe(addr string, port int) {

	// Trigger subscription requests async.
	go client.Start()

	log.Printf("Starting HTTP server on %s:%d", addr, port)
	log.Fatal(http.ListenAndServe(fmt.Sprintf("%s:%d", addr, port), client.defaultHTTPHandler()))
}

func (client *Client) StartAndServeTLS(addr string, port int, certFile, keyFile string) {
	client.https = true

	// Trigger subscription requests async.
	go client.Start()

	log.Printf("Starting HTTPS server on %s:%d", addr, port)
	log.Fatal(http.ListenAndServeTLS(fmt.Sprintf("%s:%d", addr, port), certFile, keyFile, client.defaultHTTPHandler()))
}

// RegisterHandler binds the client's HandlerFunc to the provided MUX on the
// path /push-callback/
func (client *Client) RegisterHandler(mux *http.ServeMux) {
	mux.HandleFunc("/push-callback/", client.handleCallback)
}

// Start makes the initial subscription requests and marks the client as running.
// Before calling, RegisterHandler should be called with a running server.
func (client *Client) Start() {
	if client.running {
		return
	}

	client.running = true
	client.ensureSubscribed()
}

// String provides a textual representation of the client's current state.
func (client Client) String() string {
	urls := make([]string, len(client.subscriptions))
	i := 0
	for k, _ := range client.subscriptions {
		urls[i] = k
		i++
	}
	return fmt.Sprintf("%d subscription(s): %v", len(client.subscriptions), urls)
}

func (client *Client) ensureSubscribed() {
	for _, s := range client.subscriptions {
		// Try to renew the subscription if the lease expires within an hour.
		oneHourAgo := time.Now().Add(-time.Hour)
		expireTime := s.verifiedAt.Add(s.lease)
		if expireTime.Before(oneHourAgo) {
			client.makeSubscriptionRequest(s)
		}
	}
	time.AfterFunc(time.Minute, client.ensureSubscribed)
}

func (client *Client) makeSubscriptionRequest(s *subscription) {
	callbackUrl := client.formatCallbackURL(s.id)

	log.Println("Subscribing to", s.topic, "waiting for callback on", callbackUrl)

	body := url.Values{}
	body.Set("hub.callback", callbackUrl)
	body.Add("hub.topic", s.topic)
	body.Add("hub.mode", "subscribe")
	if s.lease != 0 {
		body.Set("hub.lease_seconds", fmt.Sprintf("%d", uint32(s.lease.Seconds())))
	}
	if client.hubSecretKey != nil {
		body.Set("hub.secret", string(*client.hubSecretKey))
	}

	req, _ := http.NewRequest("POST", s.hub, bytes.NewBufferString(body.Encode()))
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Add("From", client.from)

	resp, err := client.httpRequester.Do(req)

	if err != nil {
		log.Printf("Subscription failed, %s, %s", *s, err)

	} else if resp.StatusCode != 202 {
		log.Printf("Subscription failed, %s, status = %s", *s, resp.Status)
	}
}

func (client *Client) makeUnsubscribeRequeast(s *subscription) {
	log.Println("Unsubscribing from", s.topic)

	body := url.Values{}
	body.Set("hub.callback", client.formatCallbackURL(s.id))
	body.Add("hub.topic", s.topic)
	body.Add("hub.mode", "unsubscribe")

	req, _ := http.NewRequest("POST", s.hub, bytes.NewBufferString(body.Encode()))
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Add("From", client.from)

	resp, err := client.httpRequester.Do(req)

	if err != nil {
		log.Printf("Unsubscribe failed, %s, %s", *s, err)

	} else if resp.StatusCode != 202 {
		log.Printf("Unsubscribe failed, %s status = %s", *s, resp.Status)
	}
}

func (client *Client) formatCallbackURL(callback uuid.UUID) string {
	var secureProtocolSuffix string
	if client.https {
		secureProtocolSuffix = "s"
	}
	return fmt.Sprintf("http%s://%s/push-callback/%s", secureProtocolSuffix, client.self, callback.String())
}

func handleDefaultRequest(resp http.ResponseWriter, req *http.Request) {
	resp.Header().Set("Content-Type", "text/plain; charset=utf-8")
	resp.Write([]byte("gohubbub ok"))
	log.Println("Request on", req.URL.Path)
}

func (client *Client) handleCallback(resp http.ResponseWriter, req *http.Request) {
	defer req.Body.Close()
	requestBody, err := ioutil.ReadAll(req.Body)

	if err != nil {
		log.Printf("Error reading callback request, %s", err)
		return
	}

	params := req.URL.Query()
	topic := params.Get("hub.topic")

	switch params.Get("hub.mode") {
	case "subscribe":
		if s, exists := client.subscriptions[topic]; exists {
			s.verifiedAt = time.Now()
			lease, err := strconv.Atoi(params.Get("hub.lease_seconds"))
			if err == nil {
				s.lease = time.Second * time.Duration(lease)
			}

			log.Printf("Subscription verified for %s, lease is %s", topic, s.lease)
			resp.Write([]byte(params.Get("hub.challenge")))

		} else {
			log.Printf("Unexpected subscription for %s", topic)

			/*
				https://www.w3.org/TR/websub/#verification-details
				The subscriber MUST confirm that the hub.topic corresponds to a pending subscription or unsubscription that it wishes to carry out. [...] If the subscriber does not agree with the action, the subscriber MUST respond with a 404 "Not Found" response.
			*/
			resp.WriteHeader(http.StatusNotFound)
		}

	case "unsubscribe":
		// We optimistically removed the subscription, so only confirm the
		// unsubscribe if no subscription exists for the topic.
		if _, exists := client.subscriptions[topic]; !exists {
			log.Printf("Unsubscribe confirmed for %s", topic)
			resp.Write([]byte(params.Get("hub.challenge")))

		} else {
			log.Printf("Unexpected unsubscribe for %s", topic)

			/*
				https://www.w3.org/TR/websub/#verification-details
				The subscriber MUST confirm that the hub.topic corresponds to a pending subscription or unsubscription that it wishes to carry out. [...] If the subscriber does not agree with the action, the subscriber MUST respond with a 404 "Not Found" response.
			*/
			resp.WriteHeader(http.StatusNotFound)
		}

	case "denied":
		log.Printf("Subscription denied for %s, reason was %s", topic, params.Get("hub.reason"))
		// TODO: Don't do anything for now, should probably mark the subscription.

	default:
		s, exists := client.subscriptionForPath(req.URL.Path)
		if !exists {
			log.Printf("Callback for unknown subscription: %s %v", req.URL.String(), req.Header.Get("Link"))

			/*
				https://www.w3.org/TR/websub/#content-distribution
				The subscriber's callback URL MAY return an HTTP 410 code to indicate that the subscription has been deleted, and the hub MAY terminate the subscription if it receives that code as a response.
			*/
			resp.WriteHeader(http.StatusGone)

		} else {
			log.Printf("Update for %s", s)

			var hubSignatureHeader string
			if client.hubSecretKey != nil {
				hubSignatureHeader = req.Header.Get("X-Hub-Signature")
				if hubSignatureHeader == "" {
					log.Printf("Expected X-Hub-Signature header from Hub")
					resp.WriteHeader(http.StatusUnauthorized)
					return
				}
			}

			// Asynchronously validate X-Hub-Signature then notify the subscription handler, shouldn't affect response.
			go func() {
				if hubSignatureHeader != "" && !client.validateHubSignature(hubSignatureHeader, requestBody) {
					return
				}

				client.broadcast(s, req.Header.Get("Content-Type"), requestBody)
			}()
		}
	}

}

var supportedHMACAlgorithms map[string]crypto.Hash = map[string]crypto.Hash{
	"sha1":   crypto.SHA1,
	"sha256": crypto.SHA256,
	"sha384": crypto.SHA384,
	"sha512": crypto.SHA512,
}

func (client *Client) validateHubSignature(header string, body []byte) bool {
	/*
		https://www.w3.org/TR/websub/#signature-validation
		If the signature does not match, subscribers MUST locally ignore the message as invalid. Subscribers MAY still acknowledge this request with a 2xx response code in order to be able to process the message asynchronously and/or prevent brute-force attempts of the signature.
	*/
	headerData := strings.Split(header, "=")
	if len(headerData) != 2 {
		log.Printf("Invalid X-Hub-Signature format: %q", header)
		return false
	}
	algorithmName := headerData[0]
	hashAlgorithm, algorithmSupported := supportedHMACAlgorithms[algorithmName]
	if !algorithmSupported {
		log.Printf("Unsupported X-Hub-Signature algorithm: %q", header)
		return false
	}

	hexReceviedMAC := headerData[1]
	if hex.DecodedLen(len(hexReceviedMAC)) != hashAlgorithm.Size() {
		log.Printf("Invalid X-Hub-Signature digest length: %q", header)
		return false
	}

	receivedMac, err := hex.DecodeString(hexReceviedMAC)
	if err != nil {
		log.Printf("Failed decoding hex string: %q, %v", hexReceviedMAC, err)
		return false
	}

	mac := hmac.New(hashAlgorithm.New, *client.hubSecretKey)
	mac.Write(body)
	expectedMac := mac.Sum(nil)

	if !hmac.Equal(expectedMac, receivedMac) {
		log.Printf("Incorrect X-Hub-Signature provided: expected %x, got %x", expectedMac, receivedMac)
		return false
	}

	return true
}

func (client *Client) subscriptionForPath(path string) (*subscription, bool) {
	parts := strings.Split(path, "/")
	if len(parts) != 3 {
		return nilSubscription, false
	}
	id, err := uuid.Parse(parts[2])
	if err != nil {
		return nilSubscription, false
	}
	for _, s := range client.subscriptions {
		if s.id == id {
			return s, true
		}
	}
	return nilSubscription, false
}

// broadcast dispatches the body of a message to the subscription handler, but
// only if it isn't a duplicate.
func (client *Client) broadcast(s *subscription, contentType string, body []byte) {
	hash := md5.New().Sum(body)

	// TODO: Use expiring cache if history size increases to handle higher message
	// throughputs.
	unique := true
	client.history.Do(func(v interface{}) {
		b, ok := v.([]byte)
		if ok && bytes.Equal(hash, b) {
			unique = false
		}
	})

	if unique {
		client.history.Value = hash
		client.history = client.history.Next()
		s.handler(contentType, body)
	}
}

// Protocol cheat sheet:
// ---------------------
//
// SUBSCRIBE
// POST to hub
//
// ContentType: application/x-www-form-urlencoded
// From: gohubbub test app
//
// hub.callback The subscriber's callback URL where notifications should be delivered.
// hub.mode "subscribe" or "unsubscribe"
// hub.topic The topic URL that the subscriber wishes to subscribe to or unsubscribe from.
// hub.lease_seconds Number of seconds for which the subscriber would like to have the subscription active. Hubs MAY choose to respect this value or not, depending on their own policies. This parameter MAY be present for unsubscription requests and MUST be ignored by the hub in that case.
//
// Response should be 202 "Accepted"

// CALLBACK - Denial notification
// Request will have the following query params:
// hub.mode=denied
// hub.topic=[URL that was denied]
// hub.reason=[why it was denied (optional)]

// CALLBACK - Verification
// Request will have the following query params:
// hub.mode=subscribe or unsubscribe
// hub.topic=[URL that was denied]
// hub.challenge=[random string]
// hub.lease_seconds=[how long lease will be held]
//
// Response should be 2xx with hub.challenge in response body.
// 400 to reject

// CALLBACK - Update notification
// Content-Type
// Payload may be a diff
// Link header with rel=hub
// Link header rel=self for topic
//
// Response empty 2xx
