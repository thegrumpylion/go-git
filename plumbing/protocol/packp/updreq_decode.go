package packp

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/format/pktline"
	"github.com/go-git/go-git/v5/plumbing/protocol/packp/capability"
)

var (
	shallowLineLength        = len(shallow) + hashSize
	minCommandLength         = hashSize*2 + 2 + 1
	minCommandAndCapsLength  = minCommandLength + 1
	minPushCertAndCapsLength = len(pushCert) + 1
)

var (
	ErrEmpty                        = errors.New("empty update-request message")
	errNoCommands                   = errors.New("unexpected EOF before any command")
	errMissingCapabilitiesDelimiter = errors.New("capabilities delimiter not found")
)

func errMalformedRequest(reason string) error {
	return fmt.Errorf("malformed request: %s", reason)
}

func errInvalidHashSize(got int) error {
	return fmt.Errorf("invalid hash size: expected %d, got %d",
		hashSize, got)
}

func errInvalidHash(err error) error {
	return fmt.Errorf("invalid hash: %s", err.Error())
}

func errInvalidShallowLineLength(got int) error {
	return errMalformedRequest(fmt.Sprintf(
		"invalid shallow line length: expected %d, got %d",
		shallowLineLength, got))
}

func errInvalidCommandCapabilitiesLineLength(got int) error {
	return errMalformedRequest(fmt.Sprintf(
		"invalid command and capabilities line length: expected at least %d, got %d",
		minCommandAndCapsLength, got))
}

func errInvalidPushCertCapabilitiesLineLength(got int) error {
	return errMalformedRequest(fmt.Sprintf(
		"invalid push-cert and capabilities line length: expected at least %d, got %d",
		minPushCertAndCapsLength, got))
}

func errInvalidCommandLineLength(got int) error {
	return errMalformedRequest(fmt.Sprintf(
		"invalid command line length: expected at least %d, got %d",
		minCommandLength, got))
}

func errInvalidShallowObjId(err error) error {
	return errMalformedRequest(
		fmt.Sprintf("invalid shallow object id: %s", err.Error()))
}

func errInvalidOldObjId(err error) error {
	return errMalformedRequest(
		fmt.Sprintf("invalid old object id: %s", err.Error()))
}

func errInvalidNewObjId(err error) error {
	return errMalformedRequest(
		fmt.Sprintf("invalid new object id: %s", err.Error()))
}

func errMalformedCommand(err error) error {
	return errMalformedRequest(fmt.Sprintf(
		"malformed command: %s", err.Error()))
}

func errInvalidPushOption(err error) error {
	return errMalformedRequest(fmt.Sprintf(
		"invalid push option: %s", err.Error()))
}

// Decode reads the next update-request message form the reader and wr
func (req *ReferenceUpdateRequest) Decode(r io.Reader) error {
	var rc io.ReadCloser
	var ok bool
	rc, ok = r.(io.ReadCloser)
	if !ok {
		rc = io.NopCloser(r)
	}

	d := &updReqDecoder{r: rc, s: pktline.NewScanner(r)}
	return d.Decode(req)
}

type updReqDecoder struct {
	r   io.ReadCloser
	s   *pktline.Scanner
	req *ReferenceUpdateRequest
}

func (d *updReqDecoder) Decode(req *ReferenceUpdateRequest) error {
	d.req = req
	funcs := []func() error{
		d.scanLine,
		d.decodeShallow,
	}

	funcsCommand := []func() error{
		d.decodeCommandAndCapabilities,
		d.decodeCommands,
		d.decodePushOptions,
		d.setPackfile,
		req.validate,
	}

	funcsPushCert := []func() error{
		d.decodePushCert,
		d.decodeCommandsPushCert,
		d.decodePGPSignature,
		d.decodePushOptions,
		d.setPackfile,
		req.validate,
	}

	for _, f := range funcs {
		if err := f(); err != nil {
			return err
		}
	}

	funcsRest := funcsCommand
	if bytes.HasPrefix(d.s.Bytes(), pushCert) {
		funcsRest = funcsPushCert
	}

	for _, f := range funcsRest {
		if err := f(); err != nil {
			return err
		}
	}

	return nil
}

func (d *updReqDecoder) scanLine() error {
	if ok := d.s.Scan(); !ok {
		return d.scanErrorOr(ErrEmpty)
	}

	return nil
}

func (d *updReqDecoder) decodeShallow() error {
	b := d.s.Bytes()

	if !bytes.HasPrefix(b, shallowNoSp) {
		return nil
	}

	if len(b) != shallowLineLength {
		return errInvalidShallowLineLength(len(b))
	}

	h, err := parseHash(string(b[len(shallow):]))
	if err != nil {
		return errInvalidShallowObjId(err)
	}

	if ok := d.s.Scan(); !ok {
		return d.scanErrorOr(errNoCommands)
	}

	d.req.Shallow = &h

	return nil
}

func (d *updReqDecoder) decodeCommands() error {
	for {
		b := d.s.Bytes()
		if bytes.Equal(b, pktline.Flush) {
			return nil
		}

		c, err := parseCommand(b)
		if err != nil {
			return err
		}

		d.req.Commands = append(d.req.Commands, c)

		if ok := d.s.Scan(); !ok {
			return d.s.Err()
		}
	}
}

func (d *updReqDecoder) decodeCommandsPushCert() error {
	beginPrefix := []byte("-----BEGIN")
	for {
		b := d.s.Bytes()
		if bytes.HasPrefix(b, beginPrefix) {
			return nil
		}

		c, err := parseCommand(b)
		if err != nil {
			return err
		}

		d.req.Commands = append(d.req.Commands, c)

		if ok := d.s.Scan(); !ok {
			return d.s.Err()
		}
	}
}

func (d *updReqDecoder) decodeCommandAndCapabilities() error {
	b := d.s.Bytes()
	i := bytes.IndexByte(b, 0)
	if i == -1 {
		return errMissingCapabilitiesDelimiter
	}

	if len(b) < minCommandAndCapsLength {
		return errInvalidCommandCapabilitiesLineLength(len(b))
	}

	cmd, err := parseCommand(b[:i])
	if err != nil {
		return err
	}

	d.req.Commands = append(d.req.Commands, cmd)

	if err := d.req.Capabilities.Decode(b[i+1:]); err != nil {
		return err
	}

	if err := d.scanLine(); err != nil {
		return err
	}

	return nil
}

func (d *updReqDecoder) setPackfile() error {
	d.req.Packfile = d.r

	return nil
}

func (d *updReqDecoder) decodePushOptions() error {
	if !d.req.Capabilities.Supports(capability.PushOptions) {
		return nil
	}

	if ok := d.s.Scan(); !ok {
		return d.s.Err()
	}

	for {
		b := d.s.Bytes()

		if bytes.Equal(b, pktline.Flush) {
			return nil
		}

		o, err := parsePushOption(b)
		if err != nil {
			return err
		}

		d.req.Options = append(d.req.Options, o)

		if ok := d.s.Scan(); !ok {
			return d.s.Err()
		}
	}
}

func (d *updReqDecoder) decodePushCert() error {
	b := d.s.Bytes()
	i := bytes.IndexByte(b, 0)
	if i == -1 {
		return errMissingCapabilitiesDelimiter
	}

	if len(b) < minPushCertAndCapsLength {
		return errInvalidPushCertCapabilitiesLineLength(len(b))
	}

	if err := d.req.Capabilities.Decode(b[i+1:]); err != nil {
		return err
	}

	if err := d.scanLine(); err != nil {
		return err
	}
	b = d.s.Bytes()

	certVersionLine := []byte("certificate version 0.1\n")
	if !bytes.Equal(b, certVersionLine) {
		return fmt.Errorf("invalid push certificate version: %s", b)
	}

	d.req.Certificate = &Certificate{}

	if err := d.scanLine(); err != nil {
		return err
	}
	b = d.s.Bytes()
	pusherPrefix := []byte("pusher ")
	if !bytes.HasPrefix(b, pusherPrefix) {
		return fmt.Errorf("expected pusher prefix: %s", b)
	}
	// remove trailing LF
	pusher := string(b[len(pusherPrefix) : len(b)-1])
	d.req.Certificate.Pusher = pusher

	if err := d.scanLine(); err != nil {
		return err
	}
	b = d.s.Bytes()
	pusheePrefix := []byte("pushee ")
	if !bytes.HasPrefix(b, pusheePrefix) {
		return fmt.Errorf("expected pushee prefix: %s", b)
	}
	// remove trailing LF
	pushee := string(b[len(pusheePrefix) : len(b)-1])
	d.req.Certificate.Pushee = pushee

	if err := d.scanLine(); err != nil {
		return err
	}
	b = d.s.Bytes()
	noncePrefix := []byte("nonce ")
	if !bytes.HasPrefix(b, noncePrefix) {
		return fmt.Errorf("expected nonce prefix: %s", b)
	}
	// remove trailing LF
	nonce := string(b[len(noncePrefix) : len(b)-1])
	d.req.Certificate.Nonce = nonce

	for {
		if err := d.scanLine(); err != nil {
			return err
		}
		b = d.s.Bytes()
		if bytes.Equal(b, []byte("\n")) {
			break
		}
		fmt.Println("ignoring option", string(b))
	}

	if err := d.scanLine(); err != nil {
		return err
	}

	return nil
}

func (d *updReqDecoder) decodePGPSignature() error {
	pushCertEnd := []byte("push-cert-end\n")
	sb := strings.Builder{}

	for {
		b := d.s.Bytes()
		if bytes.Equal(b, pushCertEnd) {
			break
		}
		if _, err := sb.Write(b); err != nil {
			return err
		}
		if err := d.scanLine(); err != nil {
			return err
		}
	}
	d.req.Certificate.PGPSignature = sb.String()

	// discard the next line
	if err := d.scanLine(); err != nil {
		return err
	}

	return nil
}

func parseCommand(b []byte) (*Command, error) {
	if len(b) < minCommandLength {
		return nil, errInvalidCommandLineLength(len(b))
	}

	var (
		os, ns string
		n      plumbing.ReferenceName
	)
	cmd := strings.TrimSpace(string(b))
	if _, err := fmt.Sscanf(cmd, "%s %s %s", &os, &ns, &n); err != nil {
		return nil, errMalformedCommand(err)
	}

	oh, err := parseHash(os)
	if err != nil {
		return nil, errInvalidOldObjId(err)
	}

	nh, err := parseHash(ns)
	if err != nil {
		return nil, errInvalidNewObjId(err)
	}

	return &Command{Old: oh, New: nh, Name: n}, nil
}

func parseHash(s string) (plumbing.Hash, error) {
	if len(s) != hashSize {
		return plumbing.ZeroHash, errInvalidHashSize(len(s))
	}

	if _, err := hex.DecodeString(s); err != nil {
		return plumbing.ZeroHash, errInvalidHash(err)
	}

	h := plumbing.NewHash(s)
	return h, nil
}

func (d *updReqDecoder) scanErrorOr(origErr error) error {
	if err := d.s.Err(); err != nil {
		return err
	}

	return origErr
}

func parsePushOption(b []byte) (*Option, error) {
	i := bytes.IndexByte(b, '=')
	if i == -1 {
		return &Option{Key: string(b)}, nil
	}
	if i == 0 {
		return nil, errInvalidPushOption(errors.New("empty option key"))
	}
	if i == len(b)-1 {
		return &Option{Key: string(b[:i])}, nil
	}
	return &Option{Key: string(b[:i]), Value: string(b[i+1:])}, nil
}
