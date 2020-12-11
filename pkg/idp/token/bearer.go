package token

import (
	"context"
	"crypto"
	"fmt"

	"github.com/flynn/hubauth/pkg/kmssign"
	"github.com/flynn/hubauth/pkg/pb"
	"github.com/flynn/hubauth/pkg/signpb"
	"github.com/golang/protobuf/ptypes"
)

type bearerBuilder struct {
	kms         kmssign.KMSClient
	audienceKey kmssign.AudienceKeyNamer
}

var _ AccessTokenBuilder = (*bearerBuilder)(nil)

func NewBearerBuilder(kms kmssign.KMSClient, audienceKey kmssign.AudienceKeyNamer) AccessTokenBuilder {
	return &bearerBuilder{
		kms:         kms,
		audienceKey: audienceKey,
	}
}

func (b *bearerBuilder) Build(ctx context.Context, audience string, t *AccessTokenData) ([]byte, error) {
	keyName, err := b.audienceKey(audience)
	if err != nil {
		return nil, fmt.Errorf("token: failed to get audience key name: %w", err)
	}
	signKey := kmssign.NewPrivateKey(b.kms, keyName, crypto.SHA256)

	exp, _ := ptypes.TimestampProto(t.ExpireTime)
	iss, _ := ptypes.TimestampProto(t.IssueTime)
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

func (b *bearerBuilder) TokenType() string {
	return "Bearer"
}
