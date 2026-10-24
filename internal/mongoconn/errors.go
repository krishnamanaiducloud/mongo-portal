package mongoconn

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net/http"
	"strings"

	"go.mongodb.org/mongo-driver/v2/mongo"
)

// Kind is a coarse, client-safe classification of MongoDB errors.
type Kind string

const (
	KindInvalidInput Kind = "invalid_input"
	KindConfig       Kind = "profile_misconfigured"
	KindAuthFailed   Kind = "mongo_auth_failed"
	KindUnauthorized Kind = "mongo_unauthorized"
	KindTLS          Kind = "tls_verification_failed"
	KindUnavailable  Kind = "mongo_unavailable"
	KindTimeout      Kind = "mongo_timeout"
	KindNotFound     Kind = "not_found"
	KindDuplicate    Kind = "duplicate_key"
	KindBadQuery     Kind = "invalid_query"
	KindOther        Kind = "mongo_error"
	// KindOIDC covers MONGODB-OIDC problems the user or the administrators
	// can act on (provider mismatch, expired sign-in, mechanism disabled).
	KindOIDC Kind = "mongo_oidc_failed"
)

// Error is returned to API handlers. Msg is safe to show to the user who made
// the request; Err (the raw driver error) is for server logs only.
type Error struct {
	Kind     Kind
	Msg      string
	Code     int32
	CodeName string
	Err      error
}

func (e *Error) Error() string {
	if e.Err != nil {
		return string(e.Kind) + ": " + e.Err.Error()
	}
	return string(e.Kind) + ": " + e.Msg
}

func (e *Error) Unwrap() error { return e.Err }

// HTTPStatus maps the error kind to an HTTP status code.
func (e *Error) HTTPStatus() int {
	switch e.Kind {
	case KindInvalidInput, KindBadQuery:
		return http.StatusBadRequest
	case KindAuthFailed, KindOIDC:
		return http.StatusUnauthorized
	case KindUnauthorized:
		return http.StatusForbidden
	case KindNotFound:
		return http.StatusNotFound
	case KindDuplicate:
		return http.StatusConflict
	case KindTimeout:
		return http.StatusGatewayTimeout
	case KindTLS, KindUnavailable:
		return http.StatusServiceUnavailable
	}
	return http.StatusBadGateway
}

// Classify converts a driver error into an *Error.
func Classify(err error) *Error {
	if err == nil {
		return nil
	}
	var e *Error
	if errors.As(err, &e) {
		return e
	}

	switch {
	case errors.Is(err, ErrOIDCProviderMismatch):
		return &Error{Kind: KindOIDC, Msg: "MongoDB trusts a different identity provider or client than this connection profile. Check the profile's oidc.issuer and oidc.clientID against the server's oidcIdentityProviders.", Err: err}
	case errors.Is(err, ErrOIDCSignInRequired):
		return &Error{Kind: KindOIDC, Msg: "Your OIDC sign-in for MongoDB has expired. Connect with OIDC again.", Err: err}
	case strings.Contains(err.Error(), "MONGODB-OIDC") && (strings.Contains(err.Error(), "not enabled") || strings.Contains(err.Error(), "MechanismUnavailable")):
		return &Error{Kind: KindOIDC, Msg: "The MongoDB deployment does not accept MONGODB-OIDC (authenticationMechanisms or oidcIdentityProviders is not set on the server).", Err: err}
	}
	if isTLSError(err) {
		return &Error{Kind: KindTLS, Msg: "TLS certificate verification with MongoDB failed", Err: err}
	}
	// Only a server-reported AuthenticationFailed counts as bad credentials.
	// Timeouts or network failures during the SASL handshake must not, or
	// they would count towards account lockout.
	if serverRejectedCredentials(err) {
		return &Error{Kind: KindAuthFailed, Msg: "Authentication failed", Err: err}
	}
	if errors.Is(err, context.DeadlineExceeded) || mongo.IsTimeout(err) || isTimeoutText(err) {
		if strings.Contains(err.Error(), "server selection") {
			return &Error{Kind: KindUnavailable, Msg: "MongoDB is unreachable", Err: err}
		}
		return &Error{Kind: KindTimeout, Msg: "The operation exceeded its time limit", Err: err}
	}
	if errors.Is(err, mongo.ErrNoDocuments) {
		return &Error{Kind: KindNotFound, Msg: "Document not found", Err: err}
	}
	if mongo.IsDuplicateKeyError(err) {
		return &Error{Kind: KindDuplicate, Msg: "A document with the same unique key already exists", Code: 11000, CodeName: "DuplicateKey", Err: err}
	}

	var se mongo.ServerError
	if errors.As(err, &se) {
		var ce mongo.CommandError
		if errors.As(err, &ce) {
			return fromCode(ce.Code, ce.Name, ce.Message, err)
		}
		var we mongo.WriteException
		if errors.As(err, &we) && len(we.WriteErrors) > 0 {
			w := we.WriteErrors[0]
			return fromCode(int32(w.Code), "", w.Message, err) // #nosec G115 -- MongoDB error codes are int32 on the wire
		}
	}
	if mongo.IsNetworkError(err) || strings.Contains(err.Error(), "server selection") || strings.Contains(err.Error(), "connection(") {
		return &Error{Kind: KindUnavailable, Msg: "MongoDB is unreachable", Err: err}
	}
	if isAuthError(err) {
		// SASL conversation errors not caused by the network, e.g. the
		// server does not support the requested mechanism for this user.
		return &Error{Kind: KindAuthFailed, Msg: "Authentication failed", Err: err}
	}
	return &Error{Kind: KindOther, Msg: "MongoDB returned an error", Err: err}
}

func serverRejectedCredentials(err error) bool {
	var ce mongo.CommandError
	if errors.As(err, &ce) && ce.Code == 18 {
		return true
	}
	s := err.Error()
	return strings.Contains(s, "AuthenticationFailed") && !isTimeoutText(err)
}

func isTimeoutText(err error) bool {
	s := err.Error()
	return strings.Contains(s, "timed out") || strings.Contains(s, "i/o timeout") ||
		strings.Contains(s, "context deadline exceeded") || strings.Contains(s, "Timeout would be exceeded")
}

func fromCode(code int32, name, msg string, err error) *Error {
	e := &Error{Code: code, CodeName: name, Err: err}
	switch code {
	case 18:
		e.Kind, e.Msg = KindAuthFailed, "Authentication failed"
	case 13, 8000:
		e.Kind, e.Msg = KindUnauthorized, "Your MongoDB user is not authorized to perform this operation"
	case 26:
		e.Kind, e.Msg = KindNotFound, "Namespace not found"
	case 27:
		e.Kind, e.Msg = KindNotFound, "Index not found"
	case 50, 262:
		e.Kind, e.Msg = KindTimeout, "The operation exceeded its time limit"
	case 11000:
		e.Kind, e.Msg = KindDuplicate, "A document with the same unique key already exists"
	case 2, 9, 14, 15, 17, 40, 67, 72, 85, 86, 166, 168, 197, 15998, 16410, 17287, 28769, 31249, 40324, 40352, 40353:
		// Parse/validation errors. The server message describes the user's own
		// input and is returned to that user only.
		e.Kind, e.Msg = KindBadQuery, truncate(msg, 500)
	case 48:
		e.Kind, e.Msg = KindDuplicate, "Namespace already exists"
	case 121:
		e.Kind, e.Msg = KindBadQuery, "Document failed collection validation"
	case 6, 7, 89, 91, 189, 10107, 11600, 11602, 13435, 13436:
		e.Kind, e.Msg = KindUnavailable, "MongoDB is temporarily unavailable"
	default:
		e.Kind, e.Msg = KindOther, "MongoDB returned an error"
		if name != "" {
			e.Msg += " (" + name + ")"
		}
	}
	return e
}

func isAuthError(err error) bool {
	s := err.Error()
	return strings.Contains(s, "AuthenticationFailed") || strings.Contains(s, "auth error") ||
		strings.Contains(s, "unable to authenticate")
}

func isTLSError(err error) bool {
	var ua x509.UnknownAuthorityError
	var he x509.HostnameError
	var ci x509.CertificateInvalidError
	var cv *tls.CertificateVerificationError
	var rh tls.RecordHeaderError
	if errors.As(err, &ua) || errors.As(err, &he) || errors.As(err, &ci) || errors.As(err, &cv) || errors.As(err, &rh) {
		return true
	}
	s := err.Error()
	return strings.Contains(s, "x509:") || strings.Contains(s, "tls: ") || strings.Contains(s, "certificate")
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
