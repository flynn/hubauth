package hmacpb

import (
	"crypto/hmac"
	"crypto/sha256"
	"testing"

	"github.com/flynn/hubauth/pkg/pb"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func TestSignMarshal(t *testing.T) {
	key := []byte("randomKey")
	data := &pb.AccessToken{ClientId: "clientID"}

	mdata, err := proto.Marshal(data)
	require.NoError(t, err)

	h := hmac.New(sha256.New, key)
	h.Write(mdata)

	want, err := proto.Marshal(&pb.SignedData{
		Data:      mdata,
		Signature: h.Sum(nil),
	})
	require.NoError(t, err)

	got, err := SignMarshal(key, data)
	require.NoError(t, err)

	require.Equal(t, want, got)
}

func TestSignMarshalInvalidKeys(t *testing.T) {
	invalidKeys := [][]byte{
		nil,
		{},
	}

	for _, k := range invalidKeys {
		_, err := SignMarshal(k, &pb.AccessToken{ClientId: "clientID"})
		require.EqualErrorf(t, err, ErrEmptyKey.Error(), "key: %#v", k)
	}
}

func TestVerifyUnmarshal(t *testing.T) {
	key := []byte("some key")
	want := &pb.AccessToken{ClientId: "clientID"}

	m, err := proto.Marshal(want)
	require.NoError(t, err)

	h := hmac.New(sha256.New, key)
	h.Write(m)

	msg, err := proto.Marshal(&pb.SignedData{
		Data:      m,
		Signature: h.Sum(nil),
	})
	require.NoError(t, err)

	got := new(pb.AccessToken)
	err = VerifyUnmarshal([]byte("wrong key"), msg, got)
	require.EqualError(t, err, ErrInvalidSignature.Error())
	require.Empty(t, got)

	require.NoError(t, VerifyUnmarshal(key, msg, got))

	require.True(t, proto.Equal(want, got))
}

func TestVerifyUnmarshalInvalidMessage(t *testing.T) {
	token, err := proto.Marshal(&pb.AccessToken{})
	require.NoError(t, err)

	invalidMessages := [][]byte{
		token,
		[]byte("invalid"),
	}

	for _, m := range invalidMessages {
		gotMsg := new(pb.AccessToken)
		err := VerifyUnmarshal([]byte("key"), m, gotMsg)
		require.EqualError(t, err, ErrInvalidSignature.Error())
		require.Empty(t, gotMsg)
	}
}
