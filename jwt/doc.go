/*-
 * Copyright 2017 Square Inc.
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

/*
Package jwt provides an implementation of the JSON Web Token standard.

# Nested tokens

A nested token is a JWS signed by the issuer and then wrapped in a JWE. There are
two ways to obtain one:

  - signed and encrypted in process with SignedAndEncrypted (or
    SignedAndEncryptedWithAlgorithms), then NestedBuilder.Token;
  - parsed from its compact serialization with ParseSignedAndEncrypted.

Both produce a *NestedJSONWebToken, and NestedJSONWebToken.Decrypt works on
either without a serialize/parse round trip. Decrypt unwraps the JWE and then
validates the inner JWS "alg" header parameter against an allowlist:

  - for a parsed token, the allowlist is the one passed to
    ParseSignedAndEncrypted;
  - for a built token, the allowlist is the one passed to
    SignedAndEncryptedWithAlgorithms when it was supplied, and otherwise the
    algorithm(s) the builder just signed with. SignedAndEncrypted therefore keeps
    decryption of freshly built tokens working with no extra configuration, while
    still refusing an inner signature that is not what was produced.

An issuer that may sign with more than one inner algorithm should declare all of
them with SignedAndEncryptedWithAlgorithms, so a token signed with any of those
algorithms still decrypts. Declaring only a subset is what "tightening" the
allowlist means: tokens outside the subset are rejected.

Decrypt distinguishes three failure classes so callers can react to them
separately:

  - ErrDecryptionFailed: the outer JWE could not be decrypted. It wraps the
    underlying error, so errors.Is also matches jose.ErrCryptoFailure.
  - ErrSignatureAlgorithmNotAllowed: the JWE decrypted but the inner "alg" is
    outside the allowlist, or no allowlist is configured. When the inner header
    names an algorithm, errors.As exposes *jose.ErrUnexpectedSignatureAlgorithm.
  - ErrInvalidContentType: the JWE "cty" header is not JWT. ParseSignedAndEncrypted
    and the nested builders report this one at parse/build time.
*/
package jwt
