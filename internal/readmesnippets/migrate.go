package readmesnippets

import (
	"bytes"
	"context"

	"github.com/stellar/go-stellar-sdk/keypair"
	"github.com/stellar/go-stellar-sdk/xdr"

	"github.com/soroauth/soroauth-go"
)

// MigrateBaselineAndCompare backs docs/migrating.md's "Verification: same
// bytes before and after" section; see Quickstart's doc comment for how the
// snippet markers relate to markdown fenced blocks. It is never called; it
// exists only to be compiled. The parameters stand in for values a real caller
// has: the old code's output (as base64), the entry soroauth would sign, the
// signer, and the parameters the old code used.
func MigrateBaselineAndCompare(
	ctx context.Context,
	baselineB64 string,
	entry xdr.SorobanAuthorizationEntry,
	kp *keypair.Full,
	validUntilLedger uint32,
	networkPassphrase string,
) (bool, error) {
	// snippet:start migrate-verify
	// The old code's output, captured once and frozen as the baseline. It is a
	// blob from outside this program, so it is decoded at the library's bound.
	baseline, err := soroauth.DecodeAuthorizationEntry(baselineB64)
	if err != nil {
		return false, err
	}

	// The same inputs, signed with soroauth instead.
	migrated, err := soroauth.AuthorizeEntry(ctx, entry, soroauth.NewEd25519Signer(kp),
		validUntilLedger, networkPassphrase)
	if err != nil {
		return false, err
	}

	// Byte-for-byte. Anything else means the migration changed what a host
	// would see, and the difference must be explained before this becomes
	// the new signing path — see the caveats in docs/migrating.md.
	got, err := migrated.MarshalBinary()
	if err != nil {
		return false, err
	}
	want, err := baseline.MarshalBinary()
	if err != nil {
		return false, err
	}
	if !bytes.Equal(got, want) {
		return false, nil
	}
	// snippet:end migrate-verify
	return true, nil
}

// MigrateInspectBaseline backs docs/migrating.md's "When the bytes should
// differ" section: before hunting a diff by eye, inspect both sides	// structurally. See Quickstart's doc comment for how the snippet markers
// relate to markdown fenced blocks.
func MigrateInspectBaseline(baselineB64 string) error {
	// snippet:start migrate-inspect
	baseline, err := soroauth.DecodeAuthorizationEntry(baselineB64)
	if err != nil {
		return err
	}
	oldInfo, err := soroauth.Inspect(baseline)
	if err != nil {
		return err
	}
	_ = oldInfo // arm, address, nonce, expiration, signed-node flags
	// snippet:end migrate-inspect
	return nil
}
