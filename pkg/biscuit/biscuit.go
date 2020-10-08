package biscuit

import (
	"crypto/rand"
	"fmt"

	"github.com/flynn/biscuit-go"
	"github.com/flynn/biscuit-go/sig"
	"github.com/flynn/hubauth/pkg/kmssign"
)

type UserKeyPair struct {
	Public  []byte
	Private []byte
}

// GenerateSignable returns a biscuit which will only verify after being
// signed with the private key matching the given userPubkey.
func GenerateSignable(rootKey sig.Keypair, audience string, audienceKey *kmssign.Key, userPubkey []byte) ([]byte, error) {
	builder := &hubauthBuilder{
		Builder: biscuit.NewBuilder(rand.Reader, rootKey),
	}

	if err := builder.withAudienceSignature(audience, audienceKey); err != nil {
		return nil, err
	}

	if err := builder.withUserToSignFact(userPubkey); err != nil {
		return nil, err
	}

	b, err := builder.Build()
	if err != nil {
		return nil, err
	}

	return b.Serialize()
}

// Sign append a user signature on the given token and return it.
// The UserKeyPair key format to provide depends on the signature algorithm:
// - for ECDSA_P256_SHA256, the private key must be encoded in SEC 1, ASN.1 DER form,
// and the public key in PKIX, ASN.1 DER form.
func Sign(token []byte, rootPubKey sig.PublicKey, userKey *UserKeyPair) ([]byte, error) {
	b, err := biscuit.Unmarshal(token)
	if err != nil {
		return nil, fmt.Errorf("biscuit: failed to unmarshal: %w", err)
	}

	v, err := b.Verify(rootPubKey)
	if err != nil {
		return nil, fmt.Errorf("biscuit: failed to verify: %w", err)
	}
	verifier := &hubauthVerifier{
		Verifier: v,
	}

	toSignData, err := verifier.getUserToSignData(userKey.Public, b.BlockCount())
	if err != nil {
		return nil, fmt.Errorf("biscuit: failed to get to_sign data: %w", err)
	}

	if err := verifier.ensureNotAlreadyUserSigned(toSignData.DataID, userKey.Public); err != nil {
		return nil, fmt.Errorf("biscuit: previous signature check failed: %w", err)
	}

	tokenHash, err := b.SHA256Sum(b.BlockCount())
	if err != nil {
		return nil, err
	}

	signData, err := userSign(tokenHash, userKey, toSignData)
	if err != nil {
		return nil, fmt.Errorf("biscuit: signature failed: %w", err)
	}

	builder := &hubauthBlockBuilder{
		BlockBuilder: b.CreateBlock(),
	}
	if err := builder.withUserSignature(signData); err != nil {
		return nil, fmt.Errorf("biscuit: failed to create signature block: %w", err)
	}

	clientKey := sig.GenerateKeypair(rand.Reader)
	b, err = b.Append(rand.Reader, clientKey, builder.Build())
	if err != nil {
		return nil, fmt.Errorf("biscuit: failed to append signature block: %w", err)
	}

	return b.Serialize()
}

// Verify will verify the biscuit, the included audience and user signature, and return an error
// when anything is invalid.
func Verify(token []byte, rootPubKey sig.PublicKey, audience string, audienceKey *kmssign.Key) error {
	b, err := biscuit.Unmarshal(token)
	if err != nil {
		return fmt.Errorf("biscuit: failed to unmarshal: %w", err)
	}

	v, err := b.Verify(rootPubKey)
	if err != nil {
		return fmt.Errorf("biscuit: failed to verify: %w", err)
	}
	verifier := &hubauthVerifier{v}

	audienceVerificationData, err := verifier.getAudienceVerificationData(audience)
	if err != nil {
		return fmt.Errorf("biscuit: failed to retrieve audience signature data: %w", err)
	}

	if err := verifyAudienceSignature(audienceKey, audienceVerificationData); err != nil {
		return fmt.Errorf("biscuit: failed to verify audience signature: %w", err)
	}
	if err := verifier.withValidatedAudienceSignature(audienceVerificationData); err != nil {
		return fmt.Errorf("biscuit: failed to add validated signature: %w", err)
	}

	userVerificationData, err := verifier.getUserVerificationData()
	if err != nil {
		return fmt.Errorf("biscuit: failed to retrieve user signature data: %w", err)
	}

	signedTokenHash, err := b.SHA256Sum(int(userVerificationData.SignedBlockCount))
	if err != nil {
		return fmt.Errorf("biscuit: failed to generate token hash: %w", err)
	}

	if err := verifyUserSignature(signedTokenHash, userVerificationData); err != nil {
		return fmt.Errorf("biscuit: failed to verify user signature: %w", err)
	}
	if err := verifier.withValidatedUserSignature(userVerificationData); err != nil {
		return fmt.Errorf("biscuit: failed to add validated signature: %w", err)
	}

	return verifier.Verify()
}
