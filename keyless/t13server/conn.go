package t13server

import (
	"context"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
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

	state ConnectionState

	inCipher  *recordCipher
	outCipher *recordCipher

	readMu  sync.Mutex
	readBuf []byte

	writeMu sync.Mutex

	handshakeComplete bool
}

func newConn(raw net.Conn, binding []byte) *Conn {
	bindingCopy := make([]byte, len(binding))
	copy(bindingCopy, binding)
	return &Conn{
		raw:     raw,
		binding: bindingCopy,
	}
}

func (c *Conn) Binding() []byte {
	out := make([]byte, len(c.binding))
	copy(out, c.binding)
	return out
}

func (c *Conn) ConnectionState() ConnectionState {
	return c.state
}

func (c *Conn) Read(b []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()

	for len(c.readBuf) == 0 {
		innerType, payload, err := c.inCipher.decryptRecord(c.raw)
		if err != nil {
			return 0, err
		}
		if innerType == recordTypeApplicationData {
			c.readBuf = payload
			break
		}
		// Ignore other post-handshake inner types or handle alerts
	}

	n := copy(b, c.readBuf)
	c.readBuf = c.readBuf[n:]
	return n, nil
}

func (c *Conn) Write(b []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()

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
	// Attempt sending encrypted close_notify alert if handshake was complete
	if c.handshakeComplete && c.outCipher != nil {
		c.writeMu.Lock()
		closeNotifyAlert := []byte{0x01, 0x00} // warning, close_notify
		if rec, err := c.outCipher.encryptRecord(recordTypeAlert, closeNotifyAlert); err == nil {
			_ = c.raw.SetWriteDeadline(time.Now().Add(500 * time.Millisecond))
			_, _ = c.raw.Write(rec)
		}
		c.writeMu.Unlock()
	}
	return c.raw.Close()
}

func (c *Conn) LocalAddr() net.Addr                { return c.raw.LocalAddr() }
func (c *Conn) RemoteAddr() net.Addr               { return c.raw.RemoteAddr() }
func (c *Conn) SetDeadline(t time.Time) error      { return c.raw.SetDeadline(t) }
func (c *Conn) SetReadDeadline(t time.Time) error  { return c.raw.SetReadDeadline(t) }
func (c *Conn) SetWriteDeadline(t time.Time) error { return c.raw.SetWriteDeadline(t) }

func (c *Conn) handshake(ctx context.Context, s *Server) error {
	// 1. Read ClientHello
	recType, chPayload, err := readPlaintextRecord(c.raw)
	if err != nil {
		return fmt.Errorf("read client hello: %w", err)
	}
	if recType != recordTypeHandshake {
		return fmt.Errorf("expected handshake record, got %x", recType)
	}

	ch, err := parseClientHello(chPayload)
	if err != nil {
		return fmt.Errorf("parse client hello: %w", err)
	}
	if !ch.hasTLS13Version {
		return errors.New("client does not support TLS 1.3")
	}
	if len(ch.x25519KeyShare) != 32 {
		return errors.New("client did not provide X25519 key share")
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

	// Send Encrypted Server Flight (EE, Cert, CV, Finished)
	var secondFlight []byte
	recEE, err := serverHsCipher.encryptRecord(recordTypeHandshake, eeBytes)
	if err != nil {
		return err
	}
	recCert, err := serverHsCipher.encryptRecord(recordTypeHandshake, certBytes)
	if err != nil {
		return err
	}
	recCV, err := serverHsCipher.encryptRecord(recordTypeHandshake, cvBytes)
	if err != nil {
		return err
	}
	recSF, err := serverHsCipher.encryptRecord(recordTypeHandshake, sfBytes)
	if err != nil {
		return err
	}
	secondFlight = append(secondFlight, recEE...)
	secondFlight = append(secondFlight, recCert...)
	secondFlight = append(secondFlight, recCV...)
	secondFlight = append(secondFlight, recSF...)
	if _, err := c.raw.Write(secondFlight); err != nil {
		return fmt.Errorf("send server encrypted flight: %w", err)
	}

	// 10. Receive Client Finished
	cfRecType, cfBytes, err := clientHsCipher.decryptRecord(c.raw)
	if err != nil {
		return fmt.Errorf("read client finished: %w", err)
	}
	if cfRecType != recordTypeHandshake {
		return fmt.Errorf("expected client handshake record, got %x", cfRecType)
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

	clientAppKey := hkdfExpandLabel(clientAppTrafficSecret, "key", nil, 16)
	clientAppIV := hkdfExpandLabel(clientAppTrafficSecret, "iv", nil, 12)
	serverAppKey := hkdfExpandLabel(serverAppTrafficSecret, "key", nil, 16)
	serverAppIV := hkdfExpandLabel(serverAppTrafficSecret, "iv", nil, 12)

	c.inCipher, err = newRecordCipher(clientAppKey, clientAppIV)
	if err != nil {
		return err
	}
	c.outCipher, err = newRecordCipher(serverAppKey, serverAppIV)
	if err != nil {
		return err
	}

	c.state = ConnectionState{
		ServerName:         ch.serverName,
		NegotiatedProtocol: negotiatedALPN,
		CipherSuite:        0x1301,
	}
	c.handshakeComplete = true

	return nil
}

func hkdfExtract(secret, salt []byte) ([]byte, error) {
	return hkdf.Extract(sha256.New, secret, salt)
}
