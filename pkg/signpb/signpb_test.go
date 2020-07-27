package signpb

import (
	"context"
	"crypto"
	"io"
	"testing"

	"github.com/flynn/hubauth/pkg/pb"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

type mockKey struct {
	mock.Mock
}

var _ Key = (*mockKey)(nil)

func (m *mockKey) Public() crypto.PublicKey {
	args := m.Called()
	return args.Get(0).(crypto.PublicKey)
}

func (m *mockKey) HashFunc() crypto.Hash {
	args := m.Called()
	return args.Get(0).(crypto.Hash)
}

func (m *mockKey) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	args := m.Called(rand, digest, opts)
	return args.Get(0).([]byte), args.Error(1)
}

func (m *mockKey) Verify(digest, sig []byte) bool {
	args := m.Called(digest, sig)
	return args.Bool(0)
}

func TestSignMarshal(t *testing.T) {
	msg := &pb.AccessToken{
		ClientId: "some clientID",
	}

	marshalMsg, err := proto.Marshal(msg)
	require.NoError(t, err)

	alg := crypto.SHA256

	hash := alg.New()
	hash.Write(marshalMsg)
	hashedMsg := hash.Sum(nil)

	signature := []byte("signed data")

	ctx := context.Background()

	k := new(mockKey)
	k.On("HashFunc").Return(alg)
	k.On("Sign", mock.Anything, hashedMsg, opts{k, ctx}).Return(signature, nil)

	want, err := proto.Marshal(&pb.SignedData{
		Data:      marshalMsg,
		Signature: signature,
	})
	require.NoError(t, err)

	got, err := SignMarshal(ctx, k, msg)
	require.NoError(t, err)
	require.Equal(t, want, got)
}

func TestVerifyUnmarshal(t *testing.T) {
	alg := crypto.SHA256

	want := &pb.AccessToken{
		ClientId: "some ClientID",
	}

	marshalledWant, err := proto.Marshal(want)
	require.NoError(t, err)

	hash := alg.New()
	hash.Write(marshalledWant)
	sig := hash.Sum(nil)

	signed, err := proto.Marshal(&pb.SignedData{
		Data:      marshalledWant,
		Signature: sig,
	})
	require.NoError(t, err)

	k := new(mockKey)
	k.On("HashFunc").Return(alg)
	k.On("Verify", sig, sig).Return(true)

	got := new(pb.AccessToken)
	require.NoError(t, VerifyUnmarshal(k, signed, got))

	require.True(t, proto.Equal(want, got))
}

func TestVerifyUnmarshalInvalidSignature(t *testing.T) {
	sig := []byte("signature")
	signed, err := proto.Marshal(&pb.SignedData{
		Data:      []byte("some data"),
		Signature: sig,
	})
	require.NoError(t, err)

	testCases := []struct {
		marshalled   []byte
		verifyCalled bool
		verifyReturn bool
	}{
		{
			marshalled:   []byte("invalid"),
			verifyCalled: false,
		},
		{
			marshalled:   signed,
			verifyCalled: true,
			verifyReturn: false,
		},
	}

	for _, testCase := range testCases {
		k := new(mockKey)
		k.On("HashFunc").Return(crypto.SHA256)
		if testCase.verifyCalled {
			k.On("Verify", mock.Anything, sig).Return(testCase.verifyReturn)
		}

		got := new(pb.AccessToken)
		err := VerifyUnmarshal(k, testCase.marshalled, got)
		require.EqualError(t, err, ErrInvalidSignature.Error())
	}
}
