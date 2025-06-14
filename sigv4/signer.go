package sigv4

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"
)

// AWS Credentials
type Credentials struct {
	AccessKeyID     string
	SecretAccessKey string
	SessionToken    string
}

type Signer struct {
	credentials Credentials
}

func NewSigner(creds Credentials) *Signer {
	return &Signer{
		credentials: creds,
	}
}

// SignRequest adding signature to the request
func (s *Signer) SignRequest(req *http.Request, service, region string) error {
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug})))
	slog.Debug("Signing request", "method", req.Method, "url", req.URL.String(), "service", service, "region", region)

	now := time.Now().UTC()
	req.Header.Set("X-Amz-Date", now.Format("20060102T150405Z"))
	req.Header.Set("Host", req.URL.Host)

	if s.credentials.SessionToken != "" {
		req.Header.Set("X-Amz-Security-Token", s.credentials.SessionToken)
	}

	canonicalRequest := s.createCanonicalRequest(req)
	slog.Debug("Canonical Request", "request", canonicalRequest)

	stringToSign := s.createStringToSign(canonicalRequest, now, service, region)
	slog.Debug("String to Sign", "stringToSign", stringToSign)

	signingKey := s.getSigningKey(now, service, region)
	slog.Debug("Signing Key", "signingKey", hex.EncodeToString(signingKey))

	signature := s.signString(stringToSign, signingKey)
	slog.Debug("Signature", "signature", signature)

	authHeader := s.createAuthorizationHeader(req, now, service, region, signature)
	slog.Debug("Authorization Header", "authHeader", authHeader)
	req.Header.Set("Authorization", authHeader)

	return nil
}

func (s *Signer) createCanonicalRequest(req *http.Request) string {
	var buf bytes.Buffer

	buf.WriteString(req.Method)
	buf.WriteByte('\n')
	if req.URL.Path == "" {
		buf.WriteString("/")
	} else {
		buf.WriteString(req.URL.Path)
	}
	buf.WriteByte('\n')
	buf.WriteString(canonicalQueryString(req.URL.Query()))
	buf.WriteByte('\n')

	canonicalHeaders, signedHeaders := canonicalHeadersAndSignedHeaders(req.Header)
	buf.WriteString(canonicalHeaders)
	buf.WriteByte('\n')
	buf.WriteString(signedHeaders)
	buf.WriteByte('\n')
	buf.WriteString(s.payloadHash(req))

	return buf.String()
}

// createStringToSign creates the string to sign for AWS SigV4
func (s *Signer) createStringToSign(canonicalRequest string, timestamp time.Time, service, region string) string {
	var buf bytes.Buffer

	buf.WriteString("AWS4-HMAC-SHA256")
	buf.WriteByte('\n')
	buf.WriteString(timestamp.Format("20060102T150405Z"))
	buf.WriteByte('\n')

	credentialScope := fmt.Sprintf("%s/%s/%s/aws4_request", timestamp.Format("20060102"), region, service)
	buf.WriteString(credentialScope)
	buf.WriteByte('\n')

	hashedCanonicalRequest := sha256.Sum256([]byte(canonicalRequest))
	buf.WriteString(hex.EncodeToString(hashedCanonicalRequest[:]))

	return buf.String()
}

// getSigningKey creates the signing key for AWS SigV4
func (s *Signer) getSigningKey(timestamp time.Time, service, region string) []byte {
	kSecret := "AWS4" + s.credentials.SecretAccessKey
	kDate := s.sign([]byte(timestamp.Format("20060102")), []byte(kSecret))
	kRegion := s.sign([]byte(region), kDate)
	kService := s.sign([]byte(service), kRegion)
	kSigning := s.sign([]byte("aws4_request"), kService)
	return kSigning
}

// sign is a helper function to create HMAC SHA256 signature
func (s *Signer) sign(data, key []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)
}

// signString creates a hex-encoded signature for the request
func (s *Signer) signString(stringToSign string, signingKey []byte) string {
	signature := s.sign([]byte(stringToSign), signingKey)
	return hex.EncodeToString(signature)
}

// createAuthorizationHeader はAuthorizationヘッダーを作成
func (s *Signer) createAuthorizationHeader(req *http.Request, timestamp time.Time, service, region, signature string) string {
	credentialScope := fmt.Sprintf("%s/%s/%s/aws4_request", timestamp.Format("20060102"), region, service)
	credential := fmt.Sprintf("%s/%s", s.credentials.AccessKeyID, credentialScope)

	_, signedHeaders := canonicalHeadersAndSignedHeaders(req.Header)

	return fmt.Sprintf("AWS4-HMAC-SHA256 Credential=%s, SignedHeaders=%s, Signature=%s",
		credential, signedHeaders, signature)
}

// payloadHash はリクエストペイロードのハッシュを計算
func (s *Signer) payloadHash(req *http.Request) string {
	const emptyStringSHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	if req.Body == nil {
		return emptyStringSHA256
	}

	body, err := io.ReadAll(req.Body)
	if err != nil {
		return emptyStringSHA256
	}

	req.Body = io.NopCloser(bytes.NewReader(body))

	hash := sha256.Sum256(body)
	return hex.EncodeToString(hash[:])
}

// canonicalQueryString は正規クエリ文字列を返す
func canonicalQueryString(values url.Values) string {
	if len(values) == 0 {
		return ""
	}

	var params []string
	for key, vals := range values {
		for _, val := range vals {
			param := url.QueryEscape(key) + "=" + url.QueryEscape(val)
			params = append(params, param)
		}
	}

	sort.Strings(params)
	return strings.Join(params, "&")
}

// returns the canonical headers and signed headers for the request
func canonicalHeadersAndSignedHeaders(headers http.Header) (string, string) {
	var keys []string
	for key := range headers {
		keys = append(keys, strings.ToLower(key))
	}
	sort.Strings(keys)

	var canonicalHeaders bytes.Buffer
	var signedHeaders []string

	for _, key := range keys {
		if shouldSignHeader(key) {
			canonicalHeaders.WriteString(key)
			canonicalHeaders.WriteByte(':')

			values := headers[http.CanonicalHeaderKey(key)]
			canonicalHeaders.WriteString(strings.Join(values, ","))
			canonicalHeaders.WriteByte('\n')

			signedHeaders = append(signedHeaders, key)
		}
	}

	return canonicalHeaders.String(), strings.Join(signedHeaders, ";")
}

func shouldSignHeader(header string) bool {
	header = strings.ToLower(header)
	switch header {
	case "authorization", "user-agent", "x-amzn-trace-id":
		return false
	default:
		return strings.HasPrefix(header, "x-amz-") ||
			header == "host" ||
			header == "content-type" ||
			header == "content-length"
	}
}
