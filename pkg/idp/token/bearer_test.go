package token

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/flynn/hubauth/pkg/kmssign"
	"github.com/flynn/hubauth/pkg/kmssign/kmssim"
	"github.com/flynn/hubauth/pkg/pb"
	"github.com/flynn/hubauth/pkg/signpb"
	"github.com/golang/protobuf/ptypes"
	"github.com/stretchr/testify/require"
)

func audienceKeyNamer(s string) (string, error) {
	return fmt.Sprintf("%s_named", s), nil
}

func TestSignedPBBuilder(t *testing.T) {
	audienceName := "audience_url"
	audienceKeyName, _ := audienceKeyNamer(audienceName)
	kms := kmssim.NewClient([]string{audienceKeyName})

	builder := NewBearerBuilder(kms, audienceKeyNamer)

	signKey, err := kmssign.NewKey(context.Background(), kms, audienceKeyName)
	require.NoError(t, err)

	now := time.Now()
	ctx := context.Background()

	accessTokenDuration := 5 * time.Minute

	data := &AccessTokenData{
		ClientID:   "clientID",
		UserEmail:  "userEmail",
		UserID:     "userID",
		IssueTime:  now,
		ExpireTime: now.Add(accessTokenDuration),
	}

	accessTokenBytes, err := builder.Build(ctx, audienceName, data)
	require.NoError(t, err)

	got := new(pb.AccessToken)
	require.NoError(t, signpb.VerifyUnmarshal(signKey, accessTokenBytes, got))

	require.Equal(t, data.ClientID, got.ClientId)
	require.Equal(t, data.UserID, got.UserId)
	require.Equal(t, data.UserEmail, got.UserEmail)

	nowPb, _ := ptypes.TimestampProto(now)
	require.Equal(t, nowPb, got.IssueTime)

	expirePb, _ := ptypes.TimestampProto(now.Add(accessTokenDuration))
	require.Equal(t, expirePb, got.ExpireTime)
}
