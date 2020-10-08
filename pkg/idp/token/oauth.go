package token

import (
	"context"
	"crypto"
	"fmt"
	"time"

	"github.com/flynn/hubauth/pkg/kmssign"
	"github.com/flynn/hubauth/pkg/pb"
	"github.com/flynn/hubauth/pkg/signpb"
	"github.com/golang/protobuf/ptypes"
)

type signedPbBuilder struct {
	kms         kmssign.KMSClient
	audienceKey kmssign.AudienceKeyNamer
}

var _ AccessTokenBuilder = (*signedPbBuilder)(nil)

func NewSignedPBBuilder(kms kmssign.KMSClient, audienceKey kmssign.AudienceKeyNamer) AccessTokenBuilder {
	return &signedPbBuilder{
		kms:         kms,
		audienceKey: audienceKey,
	}
}

func (b *signedPbBuilder) Build(ctx context.Context, audience string, t *AccessTokenData, now time.Time, duration time.Duration) ([]byte, error) {
	signKey := kmssign.NewPrivateKey(b.kms, b.audienceKey(audience), crypto.SHA256)

	exp, _ := ptypes.TimestampProto(now.Add(duration))
	iss, _ := ptypes.TimestampProto(now)
	msg := &pb.AccessToken{
		ClientId:   t.ClientID,
		UserId:     t.UserID,
		UserEmail:  t.UserEmail,
		IssueTime:  iss,
		ExpireTime: exp,
	}
	tokenBytes, err := signpb.SignMarshal(ctx, signKey, msg)
	if err != nil {
		return nil, fmt.Errorf("token: error signing access token: %w", err)
	}

	return tokenBytes, nil
}
