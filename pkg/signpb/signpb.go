package signpb

import (
	"context"
	"crypto"
	"crypto/rand"
	"errors"

	"github.com/flynn/hubauth/pkg/pb"
	"golang.org/x/exp/errors/fmt"
	"google.golang.org/protobuf/proto"
)

type Key interface {
	PublicKey
	PrivateKey
}

type PrivateKey interface {
	crypto.Signer
	HashFunc() crypto.Hash
}

type PublicKey interface {
	HashFunc() crypto.Hash
	Verify(digest, sig []byte) bool
}

type opts struct {
	crypto.SignerOpts
	ctx context.Context
}

func (o opts) Context() context.Context {
	return o.ctx
}

func SignMarshal(ctx context.Context, k PrivateKey, msg proto.Message) ([]byte, error) {
	data, err := proto.Marshal(msg)
	if err != nil {
		return nil, fmt.Errorf("signpb: error marshalling message: %w", err)
	}

	h := k.HashFunc().New()
	h.Write(data)

	sig, err := k.Sign(rand.Reader, h.Sum(nil), opts{k, ctx})
	if err != nil {
		return nil, fmt.Errorf("signpb: error signing message: %w", err)
	}

	res, err := proto.Marshal(&pb.SignedData{Data: data, Signature: sig})
	if err != nil {
		return nil, fmt.Errorf("signpb: error marshalling signed message: %w", err)
	}

	return res, nil
}

var ErrInvalidSignature = errors.New("signpb: invalid signature")

func VerifyUnmarshal(k PublicKey, b []byte, m proto.Message) error {
	signed := &pb.SignedData{}
	if err := proto.Unmarshal(b, signed); err != nil {
		return ErrInvalidSignature
	}

	h := k.HashFunc().New()
	h.Write(signed.Data)

	if !k.Verify(h.Sum(nil), signed.Signature) {
		return ErrInvalidSignature
	}

	return proto.Unmarshal(signed.Data, m)
}
