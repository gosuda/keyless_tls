package t13server

import (
	"context"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/gosuda/keyless_tls/relay/signrpc"
)

type Conn struct {
	raw     net.Conn
	binding []byte

	server           *Server
	handshakeTimeout time.Duration

	deadlineMu    sync.Mutex
	readDeadline  time.Time
	writeDeadline time.Time

	state tls.ConnectionState

	// stateMu guards the connection-visible handshake state below: state,
	// handshakeComplete, inCipher and outCipher. Writers (the handshake) must
	// publish under it; Close() and ConnectionState() must read under it, so
	// concurrent callers always see a consistent snapshot. The Read/Write hot
	// paths are ordered by handshakeOnce instead (every caller passes through
	// handshakeOnce.Do before touching the ciphers).
	stateMu sync.Mutex

	inCipher  *recordCipher
	outCipher *recordCipher

	// exporterSecret is the TLS 1.3 exporter master secret derived during
	// the handshake (RFC 8446 Section 7.5). It is set under stateMu at the
	// same publish point as handshakeComplete and stays nil until then, so
	// ExportKeyingMaterial fails cleanly before a successful handshake.
	exporterSecret []byte

	readMu  sync.Mutex
	readBuf []byte

	writeMu sync.Mutex

	handshakeOnce     sync.Once
	handshakeErr      error
	handshakeComplete bool
}

func newConn(raw net.Conn, binding []byte, s *Server, timeout time.Duration) *Conn {
	bindingCopy := make([]byte, len(binding))
	copy(bindingCopy, binding)
	return &Conn{
		raw:              raw,
		binding:          bindingCopy,
		server:           s,
		handshakeTimeout: timeout,
	}
}

func (c *Conn) Binding() []byte {
	out := make([]byte, len(c.binding))
	copy(out, c.binding)
	return out
}

func (c *Conn) ConnectionState() ConnectionState {
	c.stateMu.Lock()
	defer c.stateMu.Unlock()
	return c.state
}

// ExportKeyingMaterial returns TLS 1.3 exported keying material for this
// connection (RFC 8446 Section 7.5), byte-identical to what a crypto/tls
// peer derives via ConnectionState.ExportKeyingMaterial for the same label,
// context, and length. Both ends of the same session produce equal output,
// which lets callers detect a relay that terminated and re-established TLS
// in between. It fails before the handshake completes and after a failed
// handshake; concurrent calls are safe.
func (c *Conn) ExportKeyingMaterial(label string, context []byte, length int) ([]byte, error) {
	c.stateMu.Lock()
	defer c.stateMu.Unlock()
	if !c.handshakeComplete || len(c.exporterSecret) == 0 {
		return nil, errors.New("tls: keying material is unavailable before a successful handshake")
	}
	if length < 0 {
		return nil, errors.New("tls: keying material length must be non-negative")
	}
	// RFC 8446 Section 7.5 derives with an empty transcript — Hash("") is a
	// 32-byte value, not an empty context field — and feeds the application
	// context only into the second expand, matching crypto/tls.
	emptyTranscript := sha256.Sum256(nil)
	derived := deriveSecret(c.exporterSecret, label, emptyTranscript[:])
	contextHash := sha256.Sum256(context)
	return hkdfExpandLabel(derived, "exporter", contextHash[:], length), nil
}

func (c *Conn) HandshakeContext(ctx context.Context) error {
	c.handshakeOnce.Do(func() {
		c.handshakeErr = c.doHandshake(ctx)
	})
	return c.handshakeErr
}

func (c *Conn) ensureHandshake() error {
	c.handshakeOnce.Do(func() {
		timeout := c.handshakeTimeout
		if timeout <= 0 {
			timeout = 10 * time.Second
		}
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		c.handshakeErr = c.doHandshake(ctx)
	})
	return c.handshakeErr
}

func earliestDeadline(d1, d2 time.Time) time.Time {
	if d1.IsZero() {
		return d2
	}
	if d2.IsZero() {
		return d1
	}
	if d1.Before(d2) {
		return d1
	}
	return d2
}

func (c *Conn) doHandshake(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	// Compute effective handshake deadline as the earliest applicable limit among:
	// 1) c.handshakeTimeout (configured maximum duration)
	// 2) ctx.Deadline() (caller context deadline)
	// 3) caller-set read / write connection deadlines
	var handshakeLimit time.Time
	if c.handshakeTimeout > 0 {
		handshakeLimit = time.Now().Add(c.handshakeTimeout)
	}
	if ctxDeadline, ok := ctx.Deadline(); ok {
		handshakeLimit = earliestDeadline(handshakeLimit, ctxDeadline)
	}

	c.deadlineMu.Lock()
	callerReadDeadline := c.readDeadline
	callerWriteDeadline := c.writeDeadline
	c.deadlineMu.Unlock()

	effectiveReadDeadline := earliestDeadline(handshakeLimit, callerReadDeadline)
	effectiveWriteDeadline := earliestDeadline(handshakeLimit, callerWriteDeadline)

	_ = c.raw.SetReadDeadline(effectiveReadDeadline)
	_ = c.raw.SetWriteDeadline(effectiveWriteDeadline)

	// Bound the entire handshake — including the remote transcript signing
	// round trip, which performs no socket I/O — by the same earliest-of
	// limit. context.WithDeadline keeps the earlier of the caller deadline
	// and handshakeLimit, so a shorter caller deadline still wins.
	if !handshakeLimit.IsZero() {
		var cancel context.CancelFunc
		ctx, cancel = context.WithDeadline(ctx, handshakeLimit)
		defer cancel()
	}

	// Unblock raw I/O stuck on the socket when the caller cancels. The restore
	// below joins the watcher (close(done) + <-watcherStopped) before touching
	// deadlines, so a late SetDeadline(past) can never overwrite the restored
	// caller-owned deadlines.
	done := make(chan struct{})
	watcherStopped := make(chan struct{})
	go func() {
		defer close(watcherStopped)
		select {
		case <-ctx.Done():
			_ = c.raw.SetDeadline(time.Unix(1, 0))
		case <-done:
		}
	}()

	// Restore caller-owned deadlines upon exiting handshake.
	defer func() {
		close(done)
		<-watcherStopped

		c.deadlineMu.Lock()
		rDeadline := c.readDeadline
		wDeadline := c.writeDeadline
		c.deadlineMu.Unlock()

		_ = c.raw.SetReadDeadline(rDeadline)
		_ = c.raw.SetWriteDeadline(wDeadline)
	}()

	err := c.handshake(ctx, c.server)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		return err
	}
	return nil
}

func (c *Conn) Read(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}

	c.readMu.Lock()
	defer c.readMu.Unlock()

	if err := c.ensureHandshake(); err != nil {
		return 0, err
	}

	for len(c.readBuf) == 0 {
		innerType, payload, err := c.inCipher.decryptRecord(c.raw)
		if err != nil {
			return 0, err
		}
		if innerType == recordTypeApplicationData {
			if len(payload) == 0 {
				continue // Skip zero-length application data records (RFC 8446 Section 5.4)
			}
			c.readBuf = payload
			break
		}
		if innerType == recordTypeHandshake {
			var msgType byte
			if len(payload) > 0 {
				msgType = payload[0]
			}
			return 0, fmt.Errorf("tls: unsupported post-handshake handshake message type 0x%02x", msgType)
		}
		return 0, fmt.Errorf("tls: unsupported record inner type 0x%02x", innerType)
	}

	n := copy(b, c.readBuf)
	c.readBuf = c.readBuf[n:]
	return n, nil
}

func (c *Conn) Write(b []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	if err := c.ensureHandshake(); err != nil {
		return 0, err
	}

	total := 0
	for len(b) > 0 {
		chunkSize := len(b)
		if chunkSize > maxPlaintextLength {
			chunkSize = maxPlaintextLength
		}
		chunk := b[:chunkSize]
		b = b[chunkSize:]

		rec, err := c.outCipher.encryptRecord(recordTypeApplicationData, chunk)
		if err != nil {
			return total, err
		}
		if _, err := c.raw.Write(rec); err != nil {
			return total, err
		}
		total += chunkSize
	}
	return total, nil
}

func (c *Conn) Close() error {
	// Attempt sending encrypted close_notify alert if handshake was complete.
	// Best-effort: use TryLock so Close() is never blocked by a concurrent Write().
	c.stateMu.Lock()
	complete := c.handshakeComplete
	outCipher := c.outCipher
	c.stateMu.Unlock()

	if complete && outCipher != nil {
		if c.writeMu.TryLock() {
			closeNotifyAlert := []byte{0x01, 0x00} // warning, close_notify
			if rec, err := outCipher.encryptRecord(recordTypeAlert, closeNotifyAlert); err == nil {
				_ = c.raw.SetWriteDeadline(time.Now().Add(100 * time.Millisecond))
				_, _ = c.raw.Write(rec)
			}
			c.writeMu.Unlock()
		}
	}
	return c.raw.Close()
}

func (c *Conn) LocalAddr() net.Addr  { return c.raw.LocalAddr() }
func (c *Conn) RemoteAddr() net.Addr { return c.raw.RemoteAddr() }

func (c *Conn) SetDeadline(t time.Time) error {
	c.deadlineMu.Lock()
	c.readDeadline = t
	c.writeDeadline = t
	c.deadlineMu.Unlock()
	return c.raw.SetDeadline(t)
}

func (c *Conn) SetReadDeadline(t time.Time) error {
	c.deadlineMu.Lock()
	c.readDeadline = t
	c.deadlineMu.Unlock()
	return c.raw.SetReadDeadline(t)
}

func (c *Conn) SetWriteDeadline(t time.Time) error {
	c.deadlineMu.Lock()
	c.writeDeadline = t
	c.deadlineMu.Unlock()
	return c.raw.SetWriteDeadline(t)
}

// writeEncryptedHandshakeMessage writes one handshake message (including its
// 4-byte header), fragmenting it across as many encrypted records as needed.
// RFC 8446 Section 5.1 allows a handshake message to span multiple records.
func (c *Conn) writeEncryptedHandshakeMessage(cipher *recordCipher, msg []byte) error {
	for len(msg) > 0 {
		fragLen := len(msg)
		if fragLen > maxPlaintextLength {
			fragLen = maxPlaintextLength
		}
		rec, err := cipher.encryptRecord(recordTypeHandshake, msg[:fragLen])
		if err != nil {
			return err
		}
		if _, err := c.raw.Write(rec); err != nil {
			return err
		}
		msg = msg[fragLen:]
	}
	return nil
}

// readEncryptedHandshakeMessage reads a single handshake message,
// reassembling it from as many encrypted records as needed.
func (c *Conn) readEncryptedHandshakeMessage(cipher *recordCipher) ([]byte, error) {
	var msgBuf []byte
	for {
		innerType, payload, err := cipher.decryptRecord(c.raw)
		if err != nil {
			return nil, err
		}
		if innerType != recordTypeHandshake {
			return nil, fmt.Errorf("%w: expected encrypted handshake record (0x16), got inner type 0x%02x", errBadRecordType, innerType)
		}
		msgBuf = append(msgBuf, payload...)

		if len(msgBuf) >= 4 {
			msgLen := int(msgBuf[1])<<16 | int(msgBuf[2])<<8 | int(msgBuf[3])
			fullLen := 4 + msgLen
			if fullLen > maxHandshakeMessageLength {
				return nil, errors.New("handshake message exceeds maximum allowed length")
			}
			if len(msgBuf) >= fullLen {
				return msgBuf[:fullLen], nil
			}
		}
	}
}

func (c *Conn) handshake(ctx context.Context, s *Server) error {
	// 1. Read ClientHello (accumulated across record boundaries)
	chPayload, err := readPlaintextHandshakeMessage(c.raw)
	if err != nil {
		return fmt.Errorf("read client hello: %w", err)
	}

	ch, err := parseClientHello(chPayload)
	if err != nil {
		return fmt.Errorf("parse client hello: %w", err)
	}
	if !ch.hasTLS13Version {
		return errors.New("client does not support TLS 1.3")
	}
	if !ch.hasAES128GCM {
		return errors.New("client does not support TLS_AES_128_GCM_SHA256 (0x1301)")
	}
	if len(ch.x25519KeyShare) != 32 {
		return errors.New("client did not provide X25519 key share")
	}
	if !ch.hasSignatureScheme(s.sigScheme) {
		return fmt.Errorf("client does not support server signature scheme 0x%04x", s.sigScheme)
	}

	// 2. Select ALPN
	negotiatedALPN := ""
	for _, serverProto := range s.cfg.NextProtos {
		for _, clientProto := range ch.alpnProtocols {
			if serverProto == clientProto {
				negotiatedALPN = serverProto
				break
			}
		}
		if negotiatedALPN != "" {
			break
		}
	}

	// 3. Generate Server Key Share (X25519)
	serverPriv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("generate x25519 key: %w", err)
	}
	serverPub := serverPriv.PublicKey().Bytes()

	// 4. Build ServerHello
	shBytes, err := buildServerHello(ch.legacySessionID, serverPub)
	if err != nil {
		return fmt.Errorf("build server hello: %w", err)
	}

	// Send ServerHello + Middlebox Compatibility Dummy CCS
	firstFlight := make([]byte, 0, len(shBytes)+5+6)
	firstFlight = append(firstFlight, formatPlaintextRecord(recordTypeHandshake, shBytes)...)
	firstFlight = append(firstFlight, recordTypeChangeCipherSpec, 0x03, 0x03, 0x00, 0x01, 0x01)
	if _, err := c.raw.Write(firstFlight); err != nil {
		return fmt.Errorf("send server hello flight: %w", err)
	}

	// 5. Compute Handshake Traffic Secrets
	clientCurvePub, err := ecdh.X25519().NewPublicKey(ch.x25519KeyShare)
	if err != nil {
		return fmt.Errorf("invalid client key share: %w", err)
	}
	sharedSecret, err := serverPriv.ECDH(clientCurvePub)
	if err != nil {
		return fmt.Errorf("ecdh failed: %w", err)
	}

	zeroKey := make([]byte, sha256.Size)
	earlySecret, err := hkdfExtract(zeroKey, nil)
	if err != nil {
		return err
	}
	emptyHash := sha256.Sum256(nil)
	derivedSecret := deriveSecret(earlySecret, "derived", emptyHash[:])
	handshakeSecret, err := hkdfExtract(sharedSecret, derivedSecret)
	if err != nil {
		return err
	}

	h1 := sha256.New()
	h1.Write(ch.raw)
	h1.Write(shBytes)
	th1 := h1.Sum(nil)

	clientHsTrafficSecret := deriveSecret(handshakeSecret, "c hs traffic", th1)
	serverHsTrafficSecret := deriveSecret(handshakeSecret, "s hs traffic", th1)

	serverHsKey := hkdfExpandLabel(serverHsTrafficSecret, "key", nil, 16)
	serverHsIV := hkdfExpandLabel(serverHsTrafficSecret, "iv", nil, 12)
	clientHsKey := hkdfExpandLabel(clientHsTrafficSecret, "key", nil, 16)
	clientHsIV := hkdfExpandLabel(clientHsTrafficSecret, "iv", nil, 12)

	serverHsCipher, err := newRecordCipher(serverHsKey, serverHsIV)
	if err != nil {
		return err
	}
	clientHsCipher, err := newRecordCipher(clientHsKey, clientHsIV)
	if err != nil {
		return err
	}

	// 6. EncryptedExtensions
	eeBytes := buildEncryptedExtensions(negotiatedALPN)

	// 7. Certificate message
	certBytes := buildCertificateMessage(s.cfg.Certificates)

	// 8. Remote CertificateVerify signing request
	nonceBytes := make([]byte, 16)
	if _, err := rand.Read(nonceBytes); err != nil {
		return fmt.Errorf("generate nonce: %w", err)
	}
	sigReq := &signrpc.TranscriptSignRequest{
		KeyID:               s.cfg.KeyID,
		Algorithm:           s.sigAlg,
		Binding:             c.binding,
		ClientHello:         ch.raw,
		ServerHello:         shBytes,
		EncryptedExtensions: eeBytes,
		Certificate:         certBytes,
		TimestampUnix:       time.Now().Unix(),
		Nonce:               hex.EncodeToString(nonceBytes),
	}

	sigResp, err := s.cfg.TranscriptSigner.SignTranscript(ctx, sigReq)
	if err != nil {
		return fmt.Errorf("remote transcript signing: %w", err)
	}
	if sigResp.KeyID != sigReq.KeyID {
		return fmt.Errorf("remote transcript signing: response key ID mismatch: got %q, want %q", sigResp.KeyID, sigReq.KeyID)
	}
	if sigResp.Algorithm != sigReq.Algorithm {
		return fmt.Errorf("remote transcript signing: response algorithm mismatch: got %q, want %q", sigResp.Algorithm, sigReq.Algorithm)
	}
	if len(sigResp.Signature) == 0 {
		return errors.New("remote transcript signing: response signature is empty")
	}

	cvBytes := buildCertificateVerify(s.sigScheme, sigResp.Signature)

	// 9. Server Finished
	h2 := sha256.New()
	h2.Write(ch.raw)
	h2.Write(shBytes)
	h2.Write(eeBytes)
	h2.Write(certBytes)
	h2.Write(cvBytes)
	th2 := h2.Sum(nil)

	serverFinishedKey := hkdfExpandLabel(serverHsTrafficSecret, "finished", nil, sha256.Size)
	mac := hmac.New(sha256.New, serverFinishedKey)
	mac.Write(th2)
	serverVerifyData := mac.Sum(nil)

	sfBytes := buildFinishedMessage(serverVerifyData)

	// Send Encrypted Server Flight (EE, Cert, CV, Finished). Each handshake
	// message is fragmented across records by its own length, so a Certificate
	// message larger than one record still fits (RFC 8446 Section 5.1).
	for _, msg := range [][]byte{eeBytes, certBytes, cvBytes, sfBytes} {
		if err := c.writeEncryptedHandshakeMessage(serverHsCipher, msg); err != nil {
			return fmt.Errorf("send server encrypted flight: %w", err)
		}
	}

	// 10. Receive Client Finished (reassembled across records if fragmented)
	cfBytes, err := c.readEncryptedHandshakeMessage(clientHsCipher)
	if err != nil {
		return fmt.Errorf("read client finished: %w", err)
	}

	clientVerifyData, err := parseFinished(cfBytes)
	if err != nil {
		return fmt.Errorf("parse client finished: %w", err)
	}

	h3 := sha256.New()
	h3.Write(ch.raw)
	h3.Write(shBytes)
	h3.Write(eeBytes)
	h3.Write(certBytes)
	h3.Write(cvBytes)
	h3.Write(sfBytes)
	th3 := h3.Sum(nil)

	clientFinishedKey := hkdfExpandLabel(clientHsTrafficSecret, "finished", nil, sha256.Size)
	mac2 := hmac.New(sha256.New, clientFinishedKey)
	mac2.Write(th3)
	expectedClientVerifyData := mac2.Sum(nil)

	if !hmac.Equal(clientVerifyData, expectedClientVerifyData) {
		return errors.New("client finished verification failed")
	}

	// 11. Derive Application Traffic Keys (RFC 8446 Section 7.1)
	derivedSecret2 := deriveSecret(handshakeSecret, "derived", emptyHash[:])
	masterSecret, err := hkdfExtract(zeroKey, derivedSecret2)
	if err != nil {
		return err
	}

	clientAppTrafficSecret := deriveSecret(masterSecret, "c ap traffic", th3)
	serverAppTrafficSecret := deriveSecret(masterSecret, "s ap traffic", th3)

	// RFC 8446 Section 7.5: the exporter master secret uses the same
	// transcript window as the application traffic secrets
	// (ClientHello...server Finished), so it is derived here and retained
	// for ExportKeyingMaterial. Two ends of the SAME session derive
	// identical exporter output; independently terminated sessions do not,
	// which is the property MITM/pass-through verification compares.
	exporterSecret := deriveSecret(masterSecret, "exp master", th3)

	clientAppKey := hkdfExpandLabel(clientAppTrafficSecret, "key", nil, 16)
	clientAppIV := hkdfExpandLabel(clientAppTrafficSecret, "iv", nil, 12)
	serverAppKey := hkdfExpandLabel(serverAppTrafficSecret, "key", nil, 16)
	serverAppIV := hkdfExpandLabel(serverAppTrafficSecret, "iv", nil, 12)

	clientAppCipher, err := newRecordCipher(clientAppKey, clientAppIV)
	if err != nil {
		return err
	}
	serverAppCipher, err := newRecordCipher(serverAppKey, serverAppIV)
	if err != nil {
		return err
	}

	// PeerCertificates and VerifiedChains intentionally stay nil: this server
	// does not perform client authentication, so there is no peer chain to
	// report. The locally presented chain goes in LocalCertificate.
	state := tls.ConnectionState{
		Version:                    tls.VersionTLS13,
		HandshakeComplete:          true,
		ServerName:                 ch.serverName,
		NegotiatedProtocol:         negotiatedALPN,
		NegotiatedProtocolIsMutual: true,
		CipherSuite:                tls.TLS_AES_128_GCM_SHA256,
		CurveID:                    tls.X25519,
		LocalCertificate:           s.cfg.Certificates,
	}

	// Publish all connection-visible handshake state together so concurrent
	// Close() / ConnectionState() readers observe a consistent snapshot.
	c.stateMu.Lock()
	c.inCipher = clientAppCipher
	c.outCipher = serverAppCipher
	c.state = state
	c.exporterSecret = exporterSecret
	c.handshakeComplete = true
	c.stateMu.Unlock()

	return nil
}

func hkdfExtract(secret, salt []byte) ([]byte, error) {
	return hkdf.Extract(sha256.New, secret, salt)
}
