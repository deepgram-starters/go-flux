/**
 * Go Flux Starter - Backend Server
 *
 * WebSocket bridge to Deepgram's Flux API via the official Go SDK (listen v2).
 * Deepgram events are received through the SDK callback and re-marshaled to the
 * browser as JSON; client audio (binary) is written to the SDK, and client text
 * control frames (CloseStream, Configure, ...) are forwarded to Deepgram. On a
 * Deepgram-side close/fatal, the browser session is torn down.
 *
 * Routes:
 *   GET  /api/session              - Issue JWT session token
 *   GET  /api/metadata             - Project metadata from deepgram.toml
 *   WS   /api/flux                 - WebSocket proxy to Deepgram Flux (auth required)
 *   GET  /health                   - Health check
 */

package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	fluxmsg "github.com/deepgram/deepgram-go-sdk/v3/pkg/api/listen/v2/websocket/interfaces"
	dginterfaces "github.com/deepgram/deepgram-go-sdk/v3/pkg/client/interfaces"
	listen "github.com/deepgram/deepgram-go-sdk/v3/pkg/client/listen"
	listenv2 "github.com/deepgram/deepgram-go-sdk/v3/pkg/client/listen/v2"

	"github.com/BurntSushi/toml"
	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/websocket"
	"github.com/joho/godotenv"
)

// ============================================================================
// CONFIGURATION
// ============================================================================

type Config struct {
	DeepgramAPIKey string
	DeepgramSTTURL string
	Port           string
	Host           string
	SessionSecret  string
}

func loadConfig() Config {
	// Load .env file (optional, won't error if missing)
	_ = godotenv.Load()

	apiKey := os.Getenv("DEEPGRAM_API_KEY")
	if apiKey == "" {
		log.Fatal("ERROR: DEEPGRAM_API_KEY environment variable is required\nPlease copy sample.env to .env and add your API key")
	}

	port := os.Getenv("PORT")
	if port == "" {
		port = "8081"
	}

	host := os.Getenv("HOST")
	if host == "" {
		host = "0.0.0.0"
	}

	sessionSecret := os.Getenv("SESSION_SECRET")
	if sessionSecret == "" {
		b := make([]byte, 32)
		if _, err := rand.Read(b); err != nil {
			log.Fatal("Failed to generate session secret:", err)
		}
		sessionSecret = hex.EncodeToString(b)
	}

	return Config{
		DeepgramAPIKey: apiKey,
		DeepgramSTTURL: "wss://api.deepgram.com/v2/listen",
		Port:           port,
		Host:           host,
		SessionSecret:  sessionSecret,
	}
}

// ============================================================================
// SESSION AUTH - JWT tokens for production security
// ============================================================================

const jwtExpiry = time.Hour

// generateToken creates a signed JWT for session authentication.
func generateToken(secret string) (string, error) {
	claims := jwt.RegisteredClaims{
		IssuedAt:  jwt.NewNumericDate(time.Now()),
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(jwtExpiry)),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(secret))
}

// validateToken verifies a JWT and returns an error if invalid.
func validateToken(tokenString, secret string) error {
	_, err := jwt.Parse(tokenString, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return []byte(secret), nil
	})
	return err
}

// validateWsToken extracts and validates a JWT from WebSocket subprotocols.
// Returns the full protocol string (e.g., "access_token.<jwt>") if valid.
func validateWsToken(protocols []string, secret string) string {
	for _, p := range protocols {
		if strings.HasPrefix(p, "access_token.") {
			tokenStr := strings.TrimPrefix(p, "access_token.")
			if err := validateToken(tokenStr, secret); err == nil {
				return p
			}
		}
	}
	return ""
}

// ============================================================================
// METADATA
// ============================================================================

// DeepgramToml represents the parsed deepgram.toml structure.
type DeepgramToml struct {
	Meta map[string]interface{} `toml:"meta"`
}

// ============================================================================
// WEBSOCKET PROXY
// ============================================================================

// upgrader configures the WebSocket upgrader. CheckOrigin allows all origins.
var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
	CheckOrigin: func(r *http.Request) bool {
		return true
	},
}

// activeConnections tracks all active client WebSocket connections for graceful shutdown.
var activeConnections sync.Map

// fluxCallback implements the Deepgram SDK FluxMessageCallback interface and
// relays Flux (listen v2) events to the browser WebSocket as JSON text frames,
// preserving the wire format the frontend already expects.
type fluxCallback struct {
	conn *websocket.Conn
	mu   *sync.Mutex
	// teardown closes the browser connection (sending a close frame) so a
	// Deepgram-initiated close/fatal propagates to the client and unblocks the
	// handler's read loop. Safe to call multiple times.
	teardown func(code int, reason string)
	// closing is set once an intentional shutdown is under way (client
	// CloseStream or teardown). While set, the transport-close "error" the SDK
	// synthesizes from Deepgram's socket close is not forwarded to the browser
	// as a spurious Error frame.
	closing *atomic.Bool
}

// send marshals a Deepgram response and writes it to the browser connection.
func (c *fluxCallback) send(v interface{}) {
	data, err := json.Marshal(v)
	if err != nil {
		log.Printf("Failed to marshal Flux event: %v", err)
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.conn.WriteMessage(websocket.TextMessage, data); err != nil {
		log.Printf("Failed to forward Flux event to client: %v", err)
	}
}

func (c *fluxCallback) Open(or *fluxmsg.OpenResponse) error { return nil }
func (c *fluxCallback) Connected(cr *fluxmsg.ConnectedResponse) error {
	c.send(cr)
	return nil
}
func (c *fluxCallback) TurnInfo(tr *fluxmsg.TurnInfoResponse) error {
	c.send(tr)
	return nil
}
func (c *fluxCallback) ConfigureSuccess(cs *fluxmsg.ConfigureSuccessResponse) error {
	c.send(cs)
	return nil
}
func (c *fluxCallback) ConfigureFailure(cf *fluxmsg.ConfigureFailureResponse) error {
	c.send(cf)
	return nil
}
func (c *fluxCallback) FatalError(fe *fluxmsg.FatalErrorResponse) error {
	c.send(fe)
	// A fatal error ends the Deepgram session; tear down the browser too.
	c.teardown(websocket.CloseInternalServerErr, "Deepgram fatal error")
	return nil
}
func (c *fluxCallback) Close(cr *fluxmsg.CloseResponse) error {
	// Deepgram closed the connection; close the browser session so the read
	// loop returns instead of blocking until the browser happens to disconnect.
	c.teardown(websocket.CloseNormalClosure, "")
	return nil
}
func (c *fluxCallback) Error(er *fluxmsg.ErrorResponse) error {
	// During an intentional shutdown the SDK reports Deepgram's socket close as
	// an error; don't forward that as a data frame — the session is already
	// ending. A real mid-session error (closing not set) is still surfaced.
	if c.closing.Load() {
		return nil
	}
	c.send(er)
	return nil
}
func (c *fluxCallback) UnhandledEvent(byData []byte) error { return nil }

// handleFluxProxy proxies WebSocket messages between the client and Deepgram's Flux API.
func handleFluxProxy(cfg Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Validate JWT from subprotocol
		protocols := websocket.Subprotocols(r)
		validProto := validateWsToken(protocols, cfg.SessionSecret)
		if validProto == "" {
			log.Println("WebSocket auth failed: invalid or missing token")
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Upgrade with the accepted subprotocol
		responseHeader := http.Header{}
		responseHeader.Set("Sec-WebSocket-Protocol", validProto)
		clientConn, err := upgrader.Upgrade(w, r, responseHeader)
		if err != nil {
			log.Printf("WebSocket upgrade failed: %v", err)
			return
		}
		defer clientConn.Close()

		log.Println("Client connected to /api/flux")
		activeConnections.Store(clientConn, true)
		defer activeConnections.Delete(clientConn)

		// Parse query parameters from client request
		query := r.URL.Query()
		model := "flux-general-en"
		encoding := query.Get("encoding")
		if encoding == "" {
			encoding = "linear16"
		}
		sampleRate := query.Get("sample_rate")
		if sampleRate == "" {
			sampleRate = "16000"
		}
		eotThreshold := query.Get("eot_threshold")
		eagerEotThreshold := query.Get("eager_eot_threshold")
		eotTimeoutMs := query.Get("eot_timeout_ms")
		keyterms := query["keyterm"] // Multi-value support

		// Build Flux transcription options from the forwarded query params.
		tOptions := &dginterfaces.FluxTranscriptionOptions{
			Model:    model,
			Encoding: encoding,
			Keyterm:  keyterms, // multi-value support
		}
		if sr, err := strconv.Atoi(sampleRate); err == nil {
			tOptions.SampleRate = sr
		}
		if eotThreshold != "" {
			if v, err := strconv.ParseFloat(eotThreshold, 64); err == nil {
				tOptions.EotThreshold = v
			}
		}
		if eagerEotThreshold != "" {
			if v, err := strconv.ParseFloat(eagerEotThreshold, 64); err == nil {
				tOptions.EagerEotThreshold = v
			}
		}
		if eotTimeoutMs != "" {
			if v, err := strconv.Atoi(eotTimeoutMs); err == nil {
				tOptions.EotTimeoutMs = v
			}
		}

		log.Printf("Connecting to Deepgram Flux: model=%s, encoding=%s, sample_rate=%s", model, encoding, sampleRate)

		// Serialize all writes to the browser connection (callback + close frames).
		writeMu := &sync.Mutex{}
		closeToClient := func(code int, msg string) {
			writeMu.Lock()
			defer writeMu.Unlock()
			clientConn.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(code, msg))
		}

		// teardown tears down the browser session exactly once: send a close
		// frame, close the connection (which unblocks clientConn.ReadMessage in
		// the pump below), and signal `done`. Invoked either by the SDK callback
		// (Deepgram close/fatal) or after a client CloseStream is drained.
		done := make(chan struct{})
		closing := &atomic.Bool{}
		var closeOnce sync.Once
		teardown := func(code int, reason string) {
			closeOnce.Do(func() {
				closing.Store(true)
				closeToClient(code, reason)
				clientConn.Close()
				close(done)
			})
		}

		// Connect to Deepgram Flux using the official Go SDK (listen v2 WebSocket).
		cOptions := &dginterfaces.ClientOptionsV2{EnableKeepAlive: true}
		callback := &fluxCallback{conn: clientConn, mu: writeMu, teardown: teardown, closing: closing}

		dgClient, err := listenv2.NewWSUsingCallback(context.Background(), cfg.DeepgramAPIKey, cOptions, tOptions, callback)
		if err != nil {
			log.Printf("Failed to create Deepgram Flux client: %v", err)
			closeToClient(websocket.CloseInternalServerErr, "Deepgram connection failed")
			return
		}

		if !dgClient.Connect() {
			log.Printf("Deepgram Flux connection failed")
			closeToClient(websocket.CloseInternalServerErr, "Deepgram connection failed")
			return
		}
		defer dgClient.Stop()

		log.Println("Connected to Deepgram Flux API")

		// Pump audio (binary) and control (text) messages from the browser to Deepgram.
		for {
			msgType, data, err := clientConn.ReadMessage()
			if err != nil {
				if websocket.IsUnexpectedCloseError(err, websocket.CloseNormalClosure, websocket.CloseGoingAway) {
					log.Printf("Client read error: %v", err)
				} else {
					log.Printf("Client disconnected")
				}
				break
			}

			switch msgType {
			case websocket.BinaryMessage:
				if _, werr := dgClient.Write(data); werr != nil {
					log.Printf("Error writing audio to Deepgram: %v", werr)
					teardown(websocket.CloseInternalServerErr, "Deepgram write failed")
					return
				}
			case websocket.TextMessage:
				// A CloseStream control message from the browser ends the session.
				// Forward it to Deepgram and wait for the server to flush its
				// final turn(s) — delivered to the browser via the callback —
				// before tearing down, rather than closing immediately and
				// racing the last finalized transcript. The Close callback fires
				// teardown; a bounded timeout guards against a missing close.
				if strings.Contains(string(data), "CloseStream") {
					log.Println("Received CloseStream from client")
					closing.Store(true)
					if werr := dgClient.WriteJSON(json.RawMessage(data)); werr != nil {
						log.Printf("Error forwarding CloseStream to Deepgram: %v", werr)
					}
					select {
					case <-done:
					case <-time.After(5 * time.Second):
						log.Println("Timed out waiting for Deepgram to finalize after CloseStream")
					}
					return
				}
				// Forward any other client control frame (e.g. a Flux Configure
				// update to thresholds/keyterms) to Deepgram verbatim instead of
				// silently dropping it.
				if werr := dgClient.WriteJSON(json.RawMessage(data)); werr != nil {
					log.Printf("Error forwarding client control message to Deepgram: %v", werr)
				}
			}
		}

		log.Println("WebSocket proxy session ended")
	}
}

// ============================================================================
// HTTP HANDLERS
// ============================================================================

// handleSession issues a signed JWT for session authentication.
func handleSession(cfg Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token, err := generateToken(cfg.SessionSecret)
		if err != nil {
			http.Error(w, `{"error":"INTERNAL_SERVER_ERROR","message":"Failed to generate token"}`, http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"token": token})
	}
}

// handleHealth returns a simple health check response.
// GET /health
func handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

// handleMetadata returns project metadata from deepgram.toml.
func handleMetadata(w http.ResponseWriter, r *http.Request) {
	var cfg DeepgramToml
	if _, err := toml.DecodeFile("deepgram.toml", &cfg); err != nil {
		log.Printf("Error reading deepgram.toml: %v", err)
		http.Error(w, `{"error":"INTERNAL_SERVER_ERROR","message":"Failed to read metadata from deepgram.toml"}`, http.StatusInternalServerError)
		return
	}
	if cfg.Meta == nil {
		http.Error(w, `{"error":"INTERNAL_SERVER_ERROR","message":"Missing [meta] section in deepgram.toml"}`, http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(cfg.Meta)
}

// corsMiddleware adds CORS headers to all responses.
func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// ============================================================================
// MAIN
// ============================================================================

func main() {
	cfg := loadConfig()

	// Initialize the Deepgram Go SDK.
	listen.InitWithDefault()

	mux := http.NewServeMux()

	// API routes
	mux.HandleFunc("GET /api/session", handleSession(cfg))
	mux.HandleFunc("GET /api/metadata", handleMetadata)
	mux.HandleFunc("GET /health", handleHealth)
	mux.HandleFunc("/api/flux", handleFluxProxy(cfg))

	// Wrap with CORS middleware
	handler := corsMiddleware(mux)

	server := &http.Server{
		Addr:    cfg.Host + ":" + cfg.Port,
		Handler: handler,
	}

	// Graceful shutdown
	go func() {
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
		sig := <-sigChan
		log.Printf("\n%s signal received: starting graceful shutdown...", sig)

		// Close all active WebSocket connections
		count := 0
		activeConnections.Range(func(key, value interface{}) bool {
			conn := key.(*websocket.Conn)
			conn.WriteMessage(websocket.CloseMessage,
				websocket.FormatCloseMessage(websocket.CloseGoingAway, "Server shutting down"))
			conn.Close()
			count++
			return true
		})
		log.Printf("Closed %d active WebSocket connection(s)", count)

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := server.Shutdown(ctx); err != nil {
			log.Printf("Server shutdown error: %v", err)
		}
		log.Println("Shutdown complete")
	}()

	log.Println(strings.Repeat("=", 70))
	log.Printf("Backend API Server running at http://localhost:%s", cfg.Port)
	log.Println("")
	log.Println("GET  /api/session")
	log.Println("WS   /api/flux (auth required)")
	log.Println("GET  /api/metadata")
	log.Println("GET  /health")
	log.Println(strings.Repeat("=", 70))

	if err := server.ListenAndServe(); err != http.ErrServerClosed {
		log.Fatalf("Server failed: %v", err)
	}
}
