/*-
 * Copyright 2016 Zbigniew Mandziejewicz
 * Copyright 2016 Square, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package jwt

import (
	"encoding/base64"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"fmt"
	"maps"
	"reflect"
	"slices"
	"strings"

	"github.com/go-jose/go-jose/v5"
)

// Builder is a utility for making JSON Web Tokens. Calls can be chained, and
// errors are accumulated until the final call to Serialize.
type Builder interface {
	// Claims encodes claims into JWE/JWS form. Multiple calls will merge claims
	// into single JSON object. If you are passing private claims, make sure to set
	// struct field tags to specify the name for the JSON key to be used when
	// serializing.
	Claims(i any) Builder
	// Token builds a JSONWebToken from provided data.
	Token() (*JSONWebToken, error)
	// Serialize serializes a token.
	Serialize() (string, error)
}

// NestedBuilder is a utility for making Signed-Then-Encrypted JSON Web Tokens.
// Calls can be chained, and errors are accumulated until final call to
// Serialize.
type NestedBuilder interface {
	// Claims encodes claims into JWE/JWS form. Multiple calls will merge claims
	// into single JSON object. If you are passing private claims, make sure to set
	// struct field tags to specify the name for the JSON key to be used when
	// serializing.
	Claims(i any) NestedBuilder
	// Token builds a NestedJSONWebToken from provided data.
	Token() (*NestedJSONWebToken, error)
	// Serialize serializes a token.
	Serialize() (string, error)
}

type builder struct {
	payload map[string]jsontext.Value
	err     error
}

type signedBuilder struct {
	builder
	sig jose.Signer
}

type encryptedBuilder struct {
	builder
	enc jose.Encrypter
}

type nestedBuilder struct {
	builder
	sig jose.Signer
	enc jose.Encrypter
	// allowedSignatureAlgorithms, when non-nil, is an explicit allowlist for the
	// inner JWS. When nil, Token derives it from the JWS this builder produces.
	allowedSignatureAlgorithms []jose.SignatureAlgorithm
}

// Signed creates builder for signed tokens.
func Signed(sig jose.Signer) Builder {
	return &signedBuilder{
		sig: sig,
	}
}

// Encrypted creates builder for encrypted tokens.
func Encrypted(enc jose.Encrypter) Builder {
	return &encryptedBuilder{
		enc: enc,
	}
}

// SignedAndEncrypted creates builder for signed-then-encrypted tokens.
// ErrInvalidContentType will be returned if encrypter doesn't have JWT content type.
//
// Tokens produced by this builder carry an inner-JWS allowlist derived from the
// algorithm(s) the signer actually used, so NestedJSONWebToken.Decrypt works on
// the token directly, without a serialization round trip. Use
// SignedAndEncryptedWithAlgorithms when an explicit allowlist is required.
func SignedAndEncrypted(sig jose.Signer, enc jose.Encrypter) NestedBuilder {
	return newNestedBuilder(sig, enc, nil)
}

// SignedAndEncryptedWithAlgorithms is like SignedAndEncrypted, but pins the
// allowlist that NestedJSONWebToken.Decrypt applies to the inner JWS "alg"
// header parameter.
//
// Passing a non-empty allowlist means a token whose inner signature uses an
// algorithm outside it is rejected with ErrSignatureAlgorithmNotAllowed at
// decryption time, even for an in-process token. Passing an empty allowlist is
// equivalent to SignedAndEncrypted.
//
// The allowlist is a property of the decryption side, not the signing side:
// issuers that may sign with more than one algorithm declare all of them here
// so that any of those tokens still decrypts.
func SignedAndEncryptedWithAlgorithms(
	sig jose.Signer,
	enc jose.Encrypter,
	allowedSignatureAlgorithms []jose.SignatureAlgorithm,
) NestedBuilder {
	return newNestedBuilder(sig, enc, allowedSignatureAlgorithms)
}

func newNestedBuilder(sig jose.Signer, enc jose.Encrypter, allowed []jose.SignatureAlgorithm) NestedBuilder {
	if contentType, _ := enc.Options().ExtraHeaders[jose.HeaderContentType].(jose.ContentType); contentType != "JWT" {
		return &nestedBuilder{
			builder: builder{
				err: ErrInvalidContentType,
			},
		}
	}
	if len(allowed) == 0 {
		allowed = nil
	} else {
		allowed = slices.Clone(allowed)
	}
	return &nestedBuilder{
		sig:                        sig,
		enc:                        enc,
		allowedSignatureAlgorithms: allowed,
	}
}

func (b builder) claims(i any) builder {
	if b.err != nil {
		return b
	}

	if m, ok := i.(map[string]jsontext.Value); ok {
		return b.merge(m)
	}

	if mapOfInterfaces, ok := i.(map[string]any); ok {
		m, err := normalize(mapOfInterfaces)
		if err != nil {
			return builder{
				err: err,
			}
		}
		return b.merge(m)
	}

	if reflect.Indirect(reflect.ValueOf(i)).Kind() == reflect.Struct {
		m, err := normalize(i)
		if err != nil {
			return builder{
				err: err,
			}
		}
		return b.merge(m)
	}

	return builder{
		err: ErrInvalidClaims,
	}
}

func normalize(i any) (map[string]jsontext.Value, error) {
	m := make(map[string]jsontext.Value)

	raw, err := json.Marshal(i, json.Deterministic(true))
	if err != nil {
		return nil, err
	}

	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, err
	}

	return m, nil
}

func (b *builder) merge(m map[string]jsontext.Value) builder {
	p := make(map[string]jsontext.Value)
	maps.Copy(p, b.payload)
	maps.Copy(p, m)

	return builder{
		payload: p,
	}
}

func (b *builder) token(p func(any) ([]byte, error), h []jose.Header) (*JSONWebToken, error) {
	return &JSONWebToken{
		payload: p,
		Headers: h,
	}, nil
}

func (b *signedBuilder) Claims(i any) Builder {
	return &signedBuilder{
		builder: b.builder.claims(i),
		sig:     b.sig,
	}
}

func (b *signedBuilder) Token() (*JSONWebToken, error) {
	sig, err := b.sign()
	if err != nil {
		return nil, err
	}

	h := make([]jose.Header, len(sig.Signatures))
	for i, v := range sig.Signatures {
		h[i] = v.Header
	}

	return b.builder.token(sig.Verify, h)
}

func (b *signedBuilder) Serialize() (string, error) {
	sig, err := b.sign()
	if err != nil {
		return "", err
	}

	return sig.CompactSerialize()
}

func (b *signedBuilder) sign() (*jose.JSONWebSignature, error) {
	if b.err != nil {
		return nil, b.err
	}

	p, err := json.Marshal(b.payload, json.Deterministic(true))
	if err != nil {
		return nil, err
	}

	return b.sig.Sign(p)
}

func (b *encryptedBuilder) Claims(i any) Builder {
	return &encryptedBuilder{
		builder: b.builder.claims(i),
		enc:     b.enc,
	}
}

func (b *encryptedBuilder) Serialize() (string, error) {
	enc, err := b.encrypt()
	if err != nil {
		return "", err
	}

	return enc.CompactSerialize()
}

func (b *encryptedBuilder) Token() (*JSONWebToken, error) {
	enc, err := b.encrypt()
	if err != nil {
		return nil, err
	}

	return b.builder.token(enc.Decrypt, []jose.Header{enc.Header})
}

func (b *encryptedBuilder) encrypt() (*jose.JSONWebEncryption, error) {
	if b.err != nil {
		return nil, b.err
	}

	p, err := json.Marshal(b.payload, json.Deterministic(true))
	if err != nil {
		return nil, err
	}

	return b.enc.Encrypt(p)
}

func (b *nestedBuilder) Claims(i any) NestedBuilder {
	return &nestedBuilder{
		builder:                    b.builder.claims(i),
		sig:                        b.sig,
		enc:                        b.enc,
		allowedSignatureAlgorithms: b.allowedSignatureAlgorithms,
	}
}

// Token produces a token that can be decrypted in-process with Decrypt, without
// a serialize/parse round trip.
//
// The inner JWS is preserved as produced by the signer, so the "alg" header
// parameter is validated against the allowlist on Decrypt exactly as it would be
// for a parsed token.
func (b *nestedBuilder) Token() (*NestedJSONWebToken, error) {
	inner, enc, err := b.signAndEncrypt()
	if err != nil {
		return nil, err
	}

	allowed := b.allowedSignatureAlgorithms
	if allowed == nil {
		allowed, err = signatureAlgorithmsOf(inner)
		if err != nil {
			return nil, err
		}
	}

	return &NestedJSONWebToken{
		allowedSignatureAlgorithms: allowed,
		enc:                        enc,
		Headers:                    []jose.Header{enc.Header},
	}, nil
}

func (b *nestedBuilder) Serialize() (string, error) {
	_, enc, err := b.signAndEncrypt()
	if err != nil {
		return "", err
	}

	return enc.CompactSerialize()
}

func (b *nestedBuilder) FullSerialize() (string, error) {
	_, enc, err := b.signAndEncrypt()
	if err != nil {
		return "", err
	}

	return enc.FullSerialize(), nil
}

// signAndEncrypt signs the claims, then encrypts the inner JWS. It returns the
// inner compact serialization that was encrypted along with the outer JWE.
// Token needs the inner serialization so it can read the "alg" header parameter
// the signer emitted, instead of guessing it, and so the allowlist is derived
// from exactly the bytes that Decrypt will later parse.
func (b *nestedBuilder) signAndEncrypt() (string, *jose.JSONWebEncryption, error) {
	if b.err != nil {
		return "", nil, b.err
	}

	p, err := json.Marshal(b.payload, json.Deterministic(true))
	if err != nil {
		return "", nil, err
	}

	sig, err := b.sig.Sign(p)
	if err != nil {
		return "", nil, err
	}

	inner, err := sig.CompactSerialize()
	if err != nil {
		return "", nil, err
	}

	enc, err := b.enc.Encrypt([]byte(inner))
	if err != nil {
		return "", nil, err
	}

	return inner, enc, nil
}

// signatureAlgorithmsOf reads the "alg" header parameter out of an inner JWS in
// compact serialization, which is what Decrypt will parse.
//
// The signer's Signature.Protected header is not populated by Sign (it is a
// merged view filled in during parsing), so the header has to be read from the
// serialized form.
func signatureAlgorithmsOf(inner string) ([]jose.SignatureAlgorithm, error) {
	encodedHeader, _, ok := strings.Cut(inner, ".")
	if !ok {
		return nil, fmt.Errorf("%w: inner signed object is not in compact serialization", ErrSignatureAlgorithmNotAllowed)
	}
	rawHeader, err := base64.RawURLEncoding.DecodeString(encodedHeader)
	if err != nil {
		return nil, fmt.Errorf("%w: cannot decode inner signature header: %w", ErrSignatureAlgorithmNotAllowed, err)
	}

	var header struct {
		Algorithm jose.SignatureAlgorithm `json:"alg"`
	}
	if err := json.Unmarshal(rawHeader, &header); err != nil {
		return nil, fmt.Errorf("%w: cannot decode inner signature header: %w", ErrSignatureAlgorithmNotAllowed, err)
	}
	if header.Algorithm == "" {
		return nil, fmt.Errorf("%w: inner signature header has no alg parameter", ErrSignatureAlgorithmNotAllowed)
	}

	return []jose.SignatureAlgorithm{header.Algorithm}, nil
}
