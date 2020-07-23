package hmacpb

import (
	"crypto/hmac"
	"crypto/sha256"
	"errors"

	"github.com/flynn/hubauth/pkg/pb"
	"golang.org/x/exp/errors/fmt"
	"google.golang.org/protobuf/proto"
)

type Key []byte

var (
	ErrEmptyKey         = errors.New("hmacpb: empty key")
	ErrInvalidSignature = errors.New("hmacpb: invalid signature")
)

func SignMarshal(k Key, msg proto.Message) ([]byte, error) {
	if len(k) == 0 {
		return nil, ErrEmptyKey
	}

	data, err := proto.Marshal(msg)
	if err != nil {
		return nil, fmt.Errorf("hmacpb: error marshalling message: %w", err)
	}

	h := hmac.New(sha256.New, k)
	h.Write(data)

	res, err := proto.Marshal(&pb.SignedData{Data: data, Signature: h.Sum(nil)})
	if err != nil {
		return nil, fmt.Errorf("hmacpb: error marshalling signed message: %w", err)
	}

	return res, nil
}

func VerifyUnmarshal(k Key, b []byte, m proto.Message) error {
	signed := &pb.SignedData{}
	if err := proto.Unmarshal(b, signed); err != nil {
		return ErrInvalidSignature
	}

	h := hmac.New(sha256.New, k)
	h.Write(signed.Data)

	if !hmac.Equal(h.Sum(nil), signed.Signature) {
		return ErrInvalidSignature
	}

	return proto.Unmarshal(signed.Data, m)
}
