# Attestation test vectors

`vectors.json` holds WebAuthn registrations made by real authenticators. They
test `VerifyAttestation`, and they are never edited by hand: the tamper tests
flip bytes in a copy at runtime.

Every vector is copied from the test data of
[go-webauthn/webauthn](https://github.com/go-webauthn/webauthn) (BSD-3-Clause),
files `protocol/attestation_packed_test.go` and `protocol/attestation_test.go`.
`clientDataJSON` and `attestationObject` are the base64url strings that library
records from the authenticator's response; `rp_id`, `origin` and `challenge` are
read back out of the client data.

| Name                               | Authenticator                                 | Format                 |
| ---------------------------------- | --------------------------------------------- | ---------------------- |
| `feitian_biopass_packed_x5c`       | FEITIAN BioPass FIDO2 USB security key        | packed, x5c (3 certs)  |
| `solokeys_solo2_packed_x5c`        | SoloKeys Solo 2 (Ed25519 key, unsupported)    | packed, x5c            |
| `virtual_authenticator_packed_x5c` | GramThanos virtual FIDO2 authenticator (soft) | packed, x5c            |
| `macos_platform_packed_self`       | macOS platform authenticator                  | packed, self           |
| `google_titan_none`                | Google Titan security key                     | none                   |
| `google_titan_fido_u2f`            | Google Titan security key                     | fido-u2f (unsupported) |
| `packed_es512_self`                | test authenticator, ES512 credential key      | packed (unsupported)   |

The virtual authenticator is software, and is included for the x5c path, not as
evidence about hardware. The last two exist to prove unsupported input is
refused.

None of these chains is anchored to a root this repository trusts. The tests
that reach `AttestationTrustRooted` use the root certificate carried inside the
vector's own x5c, which shows the chain check works and says nothing about
whether that root should be trusted.
