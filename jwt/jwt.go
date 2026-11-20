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
	"encoding/json/v2"
	"errors"
	"fmt"
	"strings"

	jose "github.com/go-jose/go-jose/v5"
)

// JSONWebToken represents a JSON Web Token (as specified in RFC7519).
type JSONWebToken struct {
	payload           func(k any) ([]byte, error)
	unverifiedPayload func() []byte
	Headers           []jose.Header
}

type NestedJSONWebToken struct {
	enc     *jose.JSONWebEncryption
	Headers []jose.Header
	// allowedSignatureAlgorithms is the allowlist applied to the "alg" header
	// parameter of the inner JWS. Tokens returned by ParseSignedAndEncrypted
	// carry the caller-supplied allowlist; tokens returned by
	// NestedBuilder.Token carry the algorithms actually present in the inner
	// JWS that the builder just produced, which is the tightest allowlist that
	// is still sound for an in-process token.
	allowedSignatureAlgorithms []jose.SignatureAlgorithm
}

// Claims deserializes a JSONWebToken into dest using the provided key.
func (t *JSONWebToken) Claims(key any, dest ...any) error {
	b, err := t.payload(key)
	if err != nil {
		return err
	}

	for _, d := range dest {
		if err := json.Unmarshal(b, d); err != nil {
			return err
		}
	}

	return nil
}

// UnsafeClaimsWithoutVerification deserializes the claims of a
// JSONWebToken into the dests. For signed JWTs, the claims are not
// verified. This function won't work for encrypted JWTs.
func (t *JSONWebToken) UnsafeClaimsWithoutVerification(dest ...any) error {
	if t.unverifiedPayload == nil {
		return fmt.Errorf("go-jose/go-jose: Cannot get unverified claims")
	}
	claims := t.unverifiedPayload()
	for _, d := range dest {
		if err := json.Unmarshal(claims, d); err != nil {
			return err
		}
	}
	return nil
}

// Decrypt decrypts the outer JWE and parses the inner JWS that it carries.
//
// The inner JWS "alg" header parameter is validated against the allowlist
// recorded on the token:
//
//   - tokens from ParseSignedAndEncrypted use the allowlist given to that
//     function;
//   - tokens from NestedBuilder.Token use the algorithm(s) the builder actually
//     signed with, unless SignedAndEncryptedWithAlgorithms supplied an explicit
//     allowlist.
//
// Errors are classified so callers can tell the failure modes apart:
//
//   - ErrDecryptionFailed: the outer JWE could not be decrypted (errors.Is also
//     matches the underlying cause, e.g. jose.ErrCryptoFailure);
//   - ErrSignatureAlgorithmNotAllowed: the JWE decrypted but the inner "alg" is
//     not in the allowlist, or no allowlist is configured (errors.As exposes
//     *jose.ErrUnexpectedSignatureAlgorithm when the header names an algorithm);
//   - ErrInvalidContentType: reported by ParseSignedAndEncrypted when the JWE
//     "cty" header is not JWT.
func (t *NestedJSONWebToken) Decrypt(decryptionKey any) (*JSONWebToken, error) {
	b, err := t.enc.Decrypt(decryptionKey)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrDecryptionFailed, err)
	}

	if len(t.allowedSignatureAlgorithms) == 0 {
		return nil, fmt.Errorf("%w: no signature algorithm allowlist configured", ErrSignatureAlgorithmNotAllowed)
	}

	sig, err := ParseSigned(string(b), t.allowedSignatureAlgorithms)
	if err != nil {
		var algErr *jose.ErrUnexpectedSignatureAlgorithm
		if errors.As(err, &algErr) {
			return nil, fmt.Errorf("%w: %w", ErrSignatureAlgorithmNotAllowed, err)
		}
		return nil, err
	}

	return sig, nil
}

// ParseSigned parses a JWT in the JWS Compact Serialization.
//
// https://datatracker.ietf.org/doc/html/rfc7515#section-3.1
//
// The signatureAlgorithms parameter contains the allowable algorithms in the "alg" header parameter.
// It must be non-empty. Non-matching algorithms cause a parse error.
func ParseSigned(s string, signatureAlgorithms []jose.SignatureAlgorithm) (*JSONWebToken, error) {
	sig, err := jose.ParseSignedCompact(s, signatureAlgorithms)
	if err != nil {
		return nil, err
	}
	headers := make([]jose.Header, len(sig.Signatures))
	for i, signature := range sig.Signatures {
		headers[i] = signature.Header
	}

	return &JSONWebToken{
		payload:           sig.Verify,
		unverifiedPayload: sig.UnsafePayloadWithoutVerification,
		Headers:           headers,
	}, nil
}

func validateKeyEncryptionAlgorithm(algs []jose.KeyAlgorithm) error {
	for _, alg := range algs {
		switch alg {
		case jose.ED25519,
			jose.RSA1_5,
			jose.RSA_OAEP,
			jose.RSA_OAEP_256,
			jose.ECDH_ES,
			jose.ECDH_ES_A128KW,
			jose.ECDH_ES_A192KW,
			jose.ECDH_ES_A256KW:
			return fmt.Errorf("asymmetric encryption algorithms not supported for JWT: "+
				"invalid key encryption algorithm: %s", alg)
		case jose.PBES2_HS256_A128KW,
			jose.PBES2_HS384_A192KW,
			jose.PBES2_HS512_A256KW:
			return fmt.Errorf("password-based encryption not supported for JWT: "+
				"invalid key encryption algorithm: %s", alg)
		}
	}
	return nil
}

func parseEncryptedCompact(
	s string,
	keyAlgorithms []jose.KeyAlgorithm,
	contentEncryption []jose.ContentEncryption,
) (*jose.JSONWebEncryption, error) {
	err := validateKeyEncryptionAlgorithm(keyAlgorithms)
	if err != nil {
		return nil, err
	}
	enc, err := jose.ParseEncryptedCompact(s, keyAlgorithms, contentEncryption)
	if err != nil {
		return nil, err
	}
	return enc, nil
}

// ParseEncrypted parses a JWT in the JWE Compact Serialization.
//
// The keyAlgorithms and contentEncryption parameters contain the allowable algorithms in the "alg" and "enc"
// header parameters respectively. They must be non-empty. Non-matching algorithms cause a parse error.
func ParseEncrypted(s string,
	keyAlgorithms []jose.KeyAlgorithm,
	contentEncryption []jose.ContentEncryption,
) (*JSONWebToken, error) {
	enc, err := parseEncryptedCompact(s, keyAlgorithms, contentEncryption)
	if err != nil {
		return nil, err
	}

	return &JSONWebToken{
		payload: enc.Decrypt,
		Headers: []jose.Header{enc.Header},
	}, nil
}

// ParseSignedAndEncrypted parses a signed-then-encrypted token in the JWE Compact Serialization.
//
// The encryptionKeyAlgorithms, contentEncryption, and signatureAlgorithms parameters contain the allowable
// algorithms. They must be non-empty. Non-matching algorithms cause a parse error.
func ParseSignedAndEncrypted(s string,
	encryptionKeyAlgorithms []jose.KeyAlgorithm,
	contentEncryption []jose.ContentEncryption,
	signatureAlgorithms []jose.SignatureAlgorithm,
) (*NestedJSONWebToken, error) {
	enc, err := parseEncryptedCompact(s, encryptionKeyAlgorithms, contentEncryption)
	if err != nil {
		return nil, err
	}

	contentType, _ := enc.Header.Other[jose.HeaderContentType]
	var cty string
	err = json.Unmarshal(contentType, &cty)
	if err != nil {
		return nil, ErrInvalidContentType
	}
	if strings.ToUpper(cty) != "JWT" {
		return nil, ErrInvalidContentType
	}

	return &NestedJSONWebToken{
		allowedSignatureAlgorithms: signatureAlgorithms,
		enc:                        enc,
		Headers:                    []jose.Header{enc.Header},
	}, nil
}
