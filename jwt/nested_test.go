/*-
 * Copyright 2024 The go-jose Authors
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
	"encoding/json/v2"
	"errors"
	"strings"
	"testing"

	"github.com/go-jose/go-jose/v5/testutils/assert"
	"github.com/go-jose/go-jose/v5/testutils/require"

	jose "github.com/go-jose/go-jose/v5"
)

// nestedTestEncryptionKey is 32 bytes so it works with A256KW / A256GCM.
var nestedTestEncryptionKey = []byte("0123456789abcdef0123456789abcdef")

// nestedTestRecipient is the standard outer wrapping used by the regression
// matrix: A256KW key wrapping with A256GCM content encryption.
func nestedTestRecipient() jose.Recipient {
	return jose.Recipient{Algorithm: jose.A256KW, Key: nestedTestEncryptionKey}
}

func newNestedTestEncrypter(t *testing.T) jose.Encrypter {
	t.Helper()
	enc, err := jose.NewEncrypter(
		jose.A256GCM,
		nestedTestRecipient(),
		(&jose.EncrypterOptions{}).WithContentType("JWT").WithType("JWT"),
	)
	require.NoError(t, err, "Error creating encrypter.")
	return enc
}

func newPS256TestSigner(t *testing.T) jose.Signer {
	t.Helper()
	sig, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.PS256, Key: testPrivRSAKey1},
		(&jose.SignerOptions{}).WithType("JWT"),
	)
	require.NoError(t, err, "Error creating PS256 signer.")
	return sig
}

// TestNestedTokenInProcessDecryptWhitelisted is matrix group 1: an algorithm on
// the allowlist decrypts in-process, without a serialization round trip, and the
// inner claims can be read back.
func TestNestedTokenInProcessDecryptWhitelisted(t *testing.T) {
	enc := newNestedTestEncrypter(t)

	// Default builder derives its allowlist from the algorithm it just signed with.
	tok, err := SignedAndEncrypted(rsaSigner, enc).Claims(&testClaims{"foo"}).Token()
	require.NoError(t, err, "Error building nested token.")

	nested, err := tok.Decrypt(nestedTestEncryptionKey)
	require.NoError(t, err, "Error decrypting nested token in-process.")

	out := &testClaims{}
	require.NoError(t, nested.Claims(&testPrivRSAKey1.PublicKey, out), "Error reading claims.")
	assert.Equal(t, testClaims{"foo"}, *out)

	// An explicit allowlist that contains the signing algorithm works the same way.
	tok2, err := SignedAndEncryptedWithAlgorithms(
		rsaSigner, enc, []jose.SignatureAlgorithm{jose.RS256},
	).Claims(&testClaims{"bar"}).Token()
	require.NoError(t, err, "Error building nested token with explicit allowlist.")

	nested2, err := tok2.Decrypt(nestedTestEncryptionKey)
	require.NoError(t, err, "Error decrypting nested token with explicit allowlist.")

	out2 := &testClaims{}
	require.NoError(t, nested2.Claims(&testPrivRSAKey1.PublicKey, out2), "Error reading claims.")
	assert.Equal(t, testClaims{"bar"}, *out2)
}

// TestNestedTokenInProcessDecryptRejectsDisallowed is matrix group 2: an inner
// algorithm outside the allowlist is rejected during in-process decryption.
func TestNestedTokenInProcessDecryptRejectsDisallowed(t *testing.T) {
	enc := newNestedTestEncrypter(t)

	tok, err := SignedAndEncryptedWithAlgorithms(
		newPS256TestSigner(t), enc, []jose.SignatureAlgorithm{jose.RS256},
	).Claims(&testClaims{"foo"}).Token()
	require.NoError(t, err, "Error building nested token.")

	nested, err := tok.Decrypt(nestedTestEncryptionKey)
	assert.Error(t, err, "Expected decryption to reject a disallowed inner algorithm.")
	assert.Equal(t, (*JSONWebToken)(nil), nested)

	if err != nil {
		assert.ErrorIs(t, err, ErrSignatureAlgorithmNotAllowed)
		var algErr *jose.ErrUnexpectedSignatureAlgorithm
		if !errors.As(err, &algErr) {
			t.Errorf("expected errors.As to expose *jose.ErrUnexpectedSignatureAlgorithm, got %T", err)
		} else {
			assert.Equal(t, jose.PS256, algErr.Got)
		}
		// A rejected algorithm must not look like a decryption failure.
		if errors.Is(err, ErrDecryptionFailed) {
			t.Error("algorithm rejection must not match ErrDecryptionFailed")
		}
		if errors.Is(err, ErrInvalidContentType) {
			t.Error("algorithm rejection must not match ErrInvalidContentType")
		}
	}
}

// TestNestedTokenInProcessDecryptMultipleDeclaredAlgorithms is matrix group 3: an
// issuer that declares two inner algorithms can decrypt tokens signed with
// either, because the allowlist carries both.
func TestNestedTokenInProcessDecryptMultipleDeclaredAlgorithms(t *testing.T) {
	enc := newNestedTestEncrypter(t)
	allowed := []jose.SignatureAlgorithm{jose.RS256, jose.PS256}

	cases := []struct {
		name   string
		signer jose.Signer
	}{
		{name: "RS256", signer: rsaSigner},
		{name: "PS256", signer: newPS256TestSigner(t)},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tok, err := SignedAndEncryptedWithAlgorithms(tc.signer, enc, allowed).
				Claims(&testClaims{"multi"}).Token()
			require.NoError(t, err, "Error building nested token.")

			nested, err := tok.Decrypt(nestedTestEncryptionKey)
			require.NoError(t, err, "Error decrypting nested token signed with %s.", tc.name)

			out := &testClaims{}
			require.NoError(t, nested.Claims(&testPrivRSAKey1.PublicKey, out), "Error reading claims.")
			assert.Equal(t, testClaims{"multi"}, *out)
		})
	}
}

// TestNestedTokenInProcessDecryptMatchesRoundTrip is matrix group 4: the
// serialize/parse path and the in-process path produce the same reading.
func TestNestedTokenInProcessDecryptMatchesRoundTrip(t *testing.T) {
	enc := newNestedTestEncrypter(t)
	b := SignedAndEncrypted(rsaSigner, enc).Claims(&testClaims{"round-trip"})

	inProcess, err := b.Token()
	require.NoError(t, err, "Error building nested token.")
	inProcessClaims := &testClaims{}
	inProcessNested, err := inProcess.Decrypt(nestedTestEncryptionKey)
	require.NoError(t, err, "Error decrypting nested token in-process.")
	require.NoError(t, inProcessNested.Claims(&testPrivRSAKey1.PublicKey, inProcessClaims), "Error reading claims.")

	serialized, err := b.Serialize()
	require.NoError(t, err, "Error serializing nested token.")
	parsed, err := ParseSignedAndEncrypted(
		serialized,
		[]jose.KeyAlgorithm{jose.A256KW},
		[]jose.ContentEncryption{jose.A256GCM},
		[]jose.SignatureAlgorithm{jose.RS256},
	)
	require.NoError(t, err, "Error parsing nested token.")
	roundTripClaims := &testClaims{}
	roundTripNested, err := parsed.Decrypt(nestedTestEncryptionKey)
	require.NoError(t, err, "Error decrypting parsed nested token.")
	require.NoError(t, roundTripNested.Claims(&testPrivRSAKey1.PublicKey, roundTripClaims), "Error reading claims.")

	assert.Equal(t, *inProcessClaims, *roundTripClaims)
	assert.Equal(t, testClaims{"round-trip"}, *inProcessClaims)
}

// TestNestedTokenErrorClassification checks that decryption failures, disallowed
// signature algorithms, and invalid content types stay distinguishable.
func TestNestedTokenErrorClassification(t *testing.T) {
	enc := newNestedTestEncrypter(t)

	tok, err := SignedAndEncrypted(rsaSigner, enc).Claims(&testClaims{"foo"}).Token()
	require.NoError(t, err, "Error building nested token.")

	t.Run("decryption failure", func(t *testing.T) {
		wrongKey := []byte("ffffffffffffffffffffffffffffffff")
		_, err := tok.Decrypt(wrongKey)
		assert.Error(t, err, "Expected decryption to fail with the wrong key.")
		if err != nil {
			assert.ErrorIs(t, err, ErrDecryptionFailed)
			assert.ErrorIs(t, err, jose.ErrCryptoFailure)
			if errors.Is(err, ErrSignatureAlgorithmNotAllowed) {
				t.Error("decryption failure must not match ErrSignatureAlgorithmNotAllowed")
			}
			if errors.Is(err, ErrInvalidContentType) {
				t.Error("decryption failure must not match ErrInvalidContentType")
			}
		}
	})

	t.Run("disallowed algorithm", func(t *testing.T) {
		disallowed, err := SignedAndEncryptedWithAlgorithms(
			newPS256TestSigner(t), enc, []jose.SignatureAlgorithm{jose.RS256},
		).Claims(&testClaims{"foo"}).Token()
		require.NoError(t, err, "Error building nested token.")

		_, err = disallowed.Decrypt(nestedTestEncryptionKey)
		assert.Error(t, err, "Expected decryption to reject the disallowed algorithm.")
		if err != nil {
			assert.ErrorIs(t, err, ErrSignatureAlgorithmNotAllowed)
			if errors.Is(err, ErrDecryptionFailed) {
				t.Error("algorithm rejection must not match ErrDecryptionFailed")
			}
			if errors.Is(err, ErrInvalidContentType) {
				t.Error("algorithm rejection must not match ErrInvalidContentType")
			}
		}
	})

	t.Run("invalid content type from parse", func(t *testing.T) {
		_, err := ParseSignedAndEncrypted(
			invalidSignedAndEncryptedToken,
			[]jose.KeyAlgorithm{jose.DIRECT},
			[]jose.ContentEncryption{jose.A128CBC_HS256},
			[]jose.SignatureAlgorithm{jose.RS256},
		)
		assert.Error(t, err, "Expected an invalid content type error.")
		if err != nil {
			assert.ErrorIs(t, err, ErrInvalidContentType)
			if errors.Is(err, ErrDecryptionFailed) {
				t.Error("content type error must not match ErrDecryptionFailed")
			}
			if errors.Is(err, ErrSignatureAlgorithmNotAllowed) {
				t.Error("content type error must not match ErrSignatureAlgorithmNotAllowed")
			}
		}
	})

	t.Run("invalid content type from builder", func(t *testing.T) {
		encNoCTY, err := jose.NewEncrypter(
			jose.A256GCM,
			nestedTestRecipient(),
			(&jose.EncrypterOptions{}).WithType("JWT"),
		)
		require.NoError(t, err, "Error creating encrypter.")

		_, err = SignedAndEncrypted(rsaSigner, encNoCTY).Claims(&testClaims{"foo"}).Token()
		assert.Error(t, err, "Expected an invalid content type error.")
		if err != nil {
			assert.ErrorIs(t, err, ErrInvalidContentType)
			if errors.Is(err, ErrDecryptionFailed) {
				t.Error("content type error must not match ErrDecryptionFailed")
			}
			if errors.Is(err, ErrSignatureAlgorithmNotAllowed) {
				t.Error("content type error must not match ErrSignatureAlgorithmNotAllowed")
			}
		}
	})
}

// TestNestedTokenAllowlistTighteningKeepsDeclaredAlgorithms checks that an issuer
// declaring several inner algorithms keeps decrypting tokens signed with any of
// them, and that narrowing the allowlist to a strict subset rejects only the
// algorithms that were dropped, never the ones still declared.
func TestNestedTokenAllowlistTighteningKeepsDeclaredAlgorithms(t *testing.T) {
	enc := newNestedTestEncrypter(t)

	build := func(t *testing.T, signer jose.Signer, allowed []jose.SignatureAlgorithm) *NestedJSONWebToken {
		t.Helper()
		tok, err := SignedAndEncryptedWithAlgorithms(signer, enc, allowed).
			Claims(&testClaims{"tightening"}).Token()
		require.NoError(t, err, "Error building nested token.")
		return tok
	}

	rsToken := build(t, rsaSigner, []jose.SignatureAlgorithm{jose.RS256, jose.PS256})
	psToken := build(t, newPS256TestSigner(t), []jose.SignatureAlgorithm{jose.RS256, jose.PS256})

	for name, tok := range map[string]*NestedJSONWebToken{"RS256": rsToken, "PS256": psToken} {
		_, err := tok.Decrypt(nestedTestEncryptionKey)
		if !assert.NoError(t, err, "Declared algorithm %s must still decrypt.", name) {
			continue
		}
	}

	// Narrow the allowlist: RS256 stays declared and must keep working, PS256 was
	// dropped and must now be refused.
	rnarrowed := build(t, rsaSigner, []jose.SignatureAlgorithm{jose.RS256})
	_, err := rnarrowed.Decrypt(nestedTestEncryptionKey)
	assert.NoError(t, err, "Tightening the allowlist must not break a still-declared algorithm.")

	psNarrowed := build(t, newPS256TestSigner(t), []jose.SignatureAlgorithm{jose.RS256})
	_, err = psNarrowed.Decrypt(nestedTestEncryptionKey)
	assert.Error(t, err, "A dropped algorithm must be refused after tightening.")
	if err != nil {
		assert.ErrorIs(t, err, ErrSignatureAlgorithmNotAllowed)
	}
}

// TestNestedTokenParseWithoutSignatureAlgorithms checks that the parsed-token
// path reports a missing allowlist as an algorithm-policy error, not as a
// decryption failure.
func TestNestedTokenParseWithoutSignatureAlgorithms(t *testing.T) {
	enc := newNestedTestEncrypter(t)

	raw, err := SignedAndEncrypted(rsaSigner, enc).Claims(&testClaims{"foo"}).Serialize()
	require.NoError(t, err, "Error serializing nested token.")

	tok, err := ParseSignedAndEncrypted(
		raw,
		[]jose.KeyAlgorithm{jose.A256KW},
		[]jose.ContentEncryption{jose.A256GCM},
		nil,
	)
	require.NoError(t, err, "Error parsing nested token.")

	_, err = tok.Decrypt(nestedTestEncryptionKey)
	assert.Error(t, err, "Expected decryption to fail without a signature allowlist.")
	if err != nil {
		assert.ErrorIs(t, err, ErrSignatureAlgorithmNotAllowed)
		if errors.Is(err, ErrDecryptionFailed) {
			t.Error("missing allowlist must not match ErrDecryptionFailed")
		}
		if errors.Is(err, ErrInvalidContentType) {
			t.Error("missing allowlist must not match ErrInvalidContentType")
		}
	}
}

// TestNestedTokenExistingPathsUnchanged guards the two pre-existing paths that
// must not be affected by the allowlist work: the plain Signed/Encrypted builders
// and the serialize-then-parse nested round trip.
func TestNestedTokenExistingPathsUnchanged(t *testing.T) {
	enc := newNestedTestEncrypter(t)

	// Non-nested construction still produces ordinary tokens.
	signedRaw, err := Signed(rsaSigner).Claims(&testClaims{"signed"}).Serialize()
	require.NoError(t, err, "Error serializing signed token.")
	signed, err := ParseSigned(signedRaw, []jose.SignatureAlgorithm{jose.RS256})
	require.NoError(t, err, "Error parsing signed token.")
	signedClaims := &testClaims{}
	require.NoError(t, signed.Claims(&testPrivRSAKey1.PublicKey, signedClaims))
	assert.Equal(t, testClaims{"signed"}, *signedClaims)

	// The nested serialize path keeps producing a compact JWE that parses back.
	raw, err := SignedAndEncrypted(rsaSigner, enc).Claims(&testClaims{"round-trip"}).Serialize()
	require.NoError(t, err, "Error serializing nested token.")
	parsed, err := ParseSignedAndEncrypted(
		raw,
		[]jose.KeyAlgorithm{jose.A256KW},
		[]jose.ContentEncryption{jose.A256GCM},
		[]jose.SignatureAlgorithm{jose.RS256},
	)
	require.NoError(t, err, "Error parsing nested token.")
	inner, err := parsed.Decrypt(nestedTestEncryptionKey)
	require.NoError(t, err, "Error decrypting nested token.")
	claims := &testClaims{}
	require.NoError(t, inner.Claims(&testPrivRSAKey1.PublicKey, claims))
	assert.Equal(t, testClaims{"round-trip"}, *claims)
}

// TestNestedTokenInProcessDecryptAcceptanceReading exercises the acceptance
// configuration end to end and logs the reading: inner RS256 signature, outer
// A256KW key wrapping with A256GCM content encryption, shared key on both sides.
//
// Run with -v to capture the reading in the delivery note.
func TestNestedTokenInProcessDecryptAcceptanceReading(t *testing.T) {
	enc := newNestedTestEncrypter(t)

	want := Claims{
		Subject: "42",
		Issuer:  "issuer",
	}
	tok, err := SignedAndEncrypted(rsaSigner, enc).Claims(want).Token()
	require.NoError(t, err, "Error building nested token.")

	nested, err := tok.Decrypt(nestedTestEncryptionKey)
	require.NoError(t, err, "Error decrypting nested token in-process.")

	got := &Claims{}
	require.NoError(t, nested.Claims(&testPrivRSAKey1.PublicKey, got), "Error reading claims.")

	outerAlg, outerEnc := tokOuterHeader(t, tok)

	t.Logf("in-process decrypt ok: %t", err == nil)
	t.Logf("recovered claims: sub=%q iss=%q", got.Subject, got.Issuer)
	t.Logf("inner alg: %s; outer alg: %s; outer enc: %s",
		innerAlgorithm(t, nested), outerAlg, outerEnc)

	assert.Equal(t, want.Subject, got.Subject)
	assert.Equal(t, want.Issuer, got.Issuer)
}

func innerAlgorithm(t *testing.T, tok *JSONWebToken) string {
	t.Helper()
	if len(tok.Headers) == 0 {
		t.Fatal("expected at least one inner header")
	}
	return tok.Headers[0].Algorithm
}

// tokOuterHeader reads the outer protected header of the token's JWE. The
// freshly built JWE only carries its parsed header after a round trip, so the
// serialization is decoded directly here.
func tokOuterHeader(t *testing.T, tok *NestedJSONWebToken) (string, string) {
	t.Helper()
	compact, err := tok.enc.CompactSerialize()
	require.NoError(t, err, "Error serializing JWE.")

	encodedHeader, _, ok := strings.Cut(compact, ".")
	if !ok {
		t.Fatal("JWE compact serialization has no header")
	}
	rawHeader, err := base64.RawURLEncoding.DecodeString(encodedHeader)
	require.NoError(t, err, "Error decoding JWE header.")

	var header struct {
		Algorithm  jose.KeyAlgorithm      `json:"alg"`
		Encryption jose.ContentEncryption `json:"enc"`
	}
	require.NoError(t, json.Unmarshal(rawHeader, &header), "Error unmarshalling JWE header.")
	return string(header.Algorithm), string(header.Encryption)
}
