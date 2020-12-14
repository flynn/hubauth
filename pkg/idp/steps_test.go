package idp

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	gdatastore "cloud.google.com/go/datastore"
	"github.com/flynn/hubauth/pkg/datastore"
	"github.com/flynn/hubauth/pkg/hmacpb"
	"github.com/flynn/hubauth/pkg/hubauth"
	"github.com/flynn/hubauth/pkg/kmssign"
	"github.com/flynn/hubauth/pkg/kmssign/kmssim"
	"github.com/flynn/hubauth/pkg/pb"
	"github.com/flynn/hubauth/pkg/signpb"
	"github.com/golang/protobuf/ptypes"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func newTestSteps(t *testing.T) *steps {
	dsc, err := gdatastore.NewClient(context.Background(), "test")
	require.NoError(t, err)

	return &steps{
		db: datastore.New(dsc),
	}
}

func TestCreateCode(t *testing.T) {
	s := newTestSteps(t)

	clientID, err := s.db.CreateClient(context.Background(), &hubauth.Client{})
	require.NoError(t, err)

	now := time.Now()
	code := &hubauth.Code{
		ClientID:      clientID,
		UserID:        "userID",
		UserEmail:     "userEmail",
		RedirectURI:   "http://redirect/uri",
		Nonce:         "nonce",
		PKCEChallenge: "challenge",
		ExpiryTime:    now,
	}

	codeID, codeSecret, err := s.CreateCode(context.Background(), code)
	require.NoError(t, err)
	require.NotEmpty(t, codeID)
	require.NotEmpty(t, codeSecret)

	storedCode, err := s.db.GetCode(context.Background(), codeID)
	require.NoError(t, err)

	require.Equal(t, code.ClientID, storedCode.ClientID)
	require.Equal(t, code.UserID, storedCode.UserID)
	require.Equal(t, code.UserEmail, storedCode.UserEmail)
	require.Equal(t, code.RedirectURI, storedCode.RedirectURI)
	require.Equal(t, code.Nonce, storedCode.Nonce)
	require.Equal(t, code.PKCEChallenge, storedCode.PKCEChallenge)
	require.Equal(t, code.ExpiryTime.Truncate(time.Millisecond), storedCode.ExpiryTime.Truncate(time.Millisecond))
	require.Equal(t, codeID, storedCode.ID)
	require.Equal(t, codeSecret, storedCode.Secret)
}

func TestVerifyCode(t *testing.T) {
	s := newTestSteps(t)

	clientID, err := s.db.CreateClient(context.Background(), &hubauth.Client{})
	require.NoError(t, err)

	codeVerifier := "someCodeVerifier"
	chall := sha256.Sum256([]byte(codeVerifier))
	challenge := base64Encode(chall[:])

	now := time.Now()
	redirectURI := "http://redirect/uri"
	code := &hubauth.Code{
		ClientID:      clientID,
		UserID:        "userID",
		UserEmail:     "userEmail",
		RedirectURI:   redirectURI,
		Nonce:         "nonce",
		PKCEChallenge: challenge,
		ExpiryTime:    now,
	}
	codeID, codeSecret, err := s.db.CreateCode(context.Background(), code)
	require.NoError(t, err)

	vc := &verifyCodeData{
		ClientID:     clientID,
		RedirectURI:  redirectURI,
		CodeVerifier: codeVerifier,
		CodeID:       codeID,
		CodeSecret:   codeSecret,
	}

	got, err := s.VerifyCode(context.Background(), vc)
	require.NoError(t, err)
	require.Equal(t, codeID, got.ID)

	// Code must have been deleted after verification
	_, err = s.db.GetCode(context.Background(), codeID)
	require.EqualError(t, errors.Unwrap(err), hubauth.ErrNotFound.Error())

	// Verifying the same code must fail, and delete any linked refresh token
	rtID, err := s.db.CreateRefreshToken(context.Background(), &hubauth.RefreshToken{
		ClientID: clientID,
		CodeID:   codeID,
	})
	require.NoError(t, err)

	_, err = s.VerifyCode(context.Background(), vc)
	require.Equal(t, &hubauth.OAuthError{
		Code:        "invalid_grant",
		Description: "code is malformed or has already been exchanged",
	}, err)
	require.Equal(t, codeID, got.ID)

	_, err = s.db.GetRefreshToken(context.Background(), rtID)
	require.Equal(t, hubauth.ErrNotFound, errors.Unwrap(err))

}

func TestVerifyCodeErrors(t *testing.T) {
	s := newTestSteps(t)

	clientID, err := s.db.CreateClient(context.Background(), &hubauth.Client{})
	require.NoError(t, err)

	codeVerifier := "someCodeVerifier"
	chall := sha256.Sum256([]byte(codeVerifier))
	challenge := base64Encode(chall[:])

	code := &hubauth.Code{
		ClientID:      clientID,
		UserID:        "userID",
		UserEmail:     "userEmail",
		RedirectURI:   "http://redirect/uri",
		Nonce:         "nonce",
		PKCEChallenge: challenge,
		ExpiryTime:    time.Now(),
	}

	validVC := &verifyCodeData{
		ClientID:     code.ClientID,
		RedirectURI:  code.RedirectURI,
		CodeVerifier: codeVerifier,
	}

	testCases := []struct {
		Err         error
		PrepareFunc func(*verifyCodeData)
	}{
		{
			Err: &hubauth.OAuthError{
				Code:        "invalid_grant",
				Description: "client_id mismatch",
			},
			PrepareFunc: func(vc *verifyCodeData) {
				vc.ClientID = "wrong"
			},
		},
		{
			Err: &hubauth.OAuthError{
				Code:        "invalid_grant",
				Description: "redirect_uri mismatch",
			},
			PrepareFunc: func(vc *verifyCodeData) {
				vc.RedirectURI = "wrong"
			},
		},
		{
			Err: &hubauth.OAuthError{
				Code:        "invalid_request",
				Description: "code_verifier mismatch",
			},
			PrepareFunc: func(vc *verifyCodeData) {
				vc.CodeVerifier = "wrong"
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.Err.Error(), func(t *testing.T) {
			codeID, codeSecret, err := s.db.CreateCode(context.Background(), code)
			require.NoError(t, err)
			tmp := *validVC
			invalidVC := &tmp
			invalidVC.CodeID = codeID
			invalidVC.CodeSecret = codeSecret
			testCase.PrepareFunc(invalidVC)

			_, err = s.VerifyCode(context.Background(), invalidVC)
			require.Equal(t, testCase.Err, err)
		})
	}
}

func TestSignCode(t *testing.T) {
	s := newTestSteps(t)

	key := make(hmacpb.Key, 32)
	_, err := rand.Read(key)
	require.NoError(t, err)

	signData := &signCodeData{
		Key:        base64Encode([]byte("key")),
		Secret:     base64Encode([]byte("secret")),
		UserID:     "userID",
		UserEmail:  "userEmail",
		ExpiryTime: time.Now(),
	}

	signedCode, err := s.SignCode(context.Background(), key, signData)
	require.NoError(t, err)

	decodedCode, err := base64Decode(signedCode)
	require.NoError(t, err)

	pbCode := new(pb.Code)
	err = hmacpb.VerifyUnmarshal(key, decodedCode, pbCode)
	require.NoError(t, err)

	require.Equal(t, signData.Key, base64Encode(pbCode.Key))
	require.Equal(t, signData.Secret, base64Encode(pbCode.Secret))
	require.Equal(t, signData.UserID, pbCode.UserId)
	require.Equal(t, signData.UserEmail, pbCode.UserEmail)
	expireTimePb, _ := ptypes.TimestampProto(signData.ExpiryTime)
	require.Equal(t, expireTimePb, pbCode.ExpireTime)
}

func TestSignCodeErrors(t *testing.T) {
	testCases := []struct {
		Desc     string
		SignData *signCodeData
	}{
		{
			Desc:     "key is not b64",
			SignData: &signCodeData{Key: "invalid b64"},
		},
		{
			Desc:     "secret is not b64",
			SignData: &signCodeData{Key: base64Encode([]byte("valid")), Secret: "invalid b64"},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.Desc, func(t *testing.T) {
			key := make(hmacpb.Key, 32)
			_, err := rand.Read(key)
			require.NoError(t, err)

			s := newTestSteps(t)
			_, err = s.SignCode(context.Background(), key, testCase.SignData)
			require.Error(t, err)
		})
	}
}

func TestVerifyAudience(t *testing.T) {
	s := newTestSteps(t)

	validAudienceURL := "http://audience/url"
	validGroupID := "validGroup"
	validUserID := "validUser"

	validClientID, err := s.db.CreateClient(context.Background(), &hubauth.Client{})
	require.NoError(t, err)

	err = s.db.CreateAudience(context.Background(), &hubauth.Audience{
		URL:       validAudienceURL,
		ClientIDs: []string{validClientID},
		UserGroups: []*hubauth.GoogleUserGroups{
			{
				Groups: []string{validGroupID},
			},
		},
	})
	require.NoError(t, err)

	_, err = s.db.SetCachedGroup(context.Background(), &hubauth.CachedGroup{
		GroupID: validGroupID,
		Domain:  "groupDomain",
	}, []*hubauth.CachedGroupMember{{UserID: validUserID}})
	require.NoError(t, err)

	testCases := []struct {
		Desc        string
		Err         error
		AudienceURL string
		ClientID    string
		UserID      string
	}{
		{
			Desc: "no audience does nothing",
			Err:  nil,
		},
		{
			Desc:        "unknown audience",
			AudienceURL: "invalid",
			Err: &hubauth.OAuthError{
				Code:        "invalid_request",
				Description: "unknown audience",
			},
		},
		{
			Desc:        "invalid client",
			AudienceURL: validAudienceURL,
			ClientID:    "invalid",
			Err: &hubauth.OAuthError{
				Code:        "invalid_client",
				Description: "unknown client for audience",
			},
		},
		{
			Desc:        "invalid user",
			AudienceURL: validAudienceURL,
			ClientID:    validClientID,
			UserID:      "invalid",
			Err: &hubauth.OAuthError{
				Code:        "access_denied",
				Description: "user is not authorized for access",
			},
		},
		{
			Desc:        "all valid no error",
			AudienceURL: validAudienceURL,
			ClientID:    validClientID,
			UserID:      validUserID,
			Err:         nil,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.Desc, func(t *testing.T) {
			err := s.VerifyAudience(context.Background(), testCase.AudienceURL, testCase.ClientID, testCase.UserID)
			if testCase.Err != nil {
				require.Equal(t, testCase.Err, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestVerifyUserGroups(t *testing.T) {
	s := newTestSteps(t)

	validUserID := "validUserID"
	_, err := s.db.SetCachedGroup(context.Background(), &hubauth.CachedGroup{
		GroupID: "group1",
		Domain:  "groupDomain",
	}, []*hubauth.CachedGroupMember{{UserID: validUserID}})
	require.NoError(t, err)

	testCases := []struct {
		Desc   string
		Err    error
		UserID string
	}{
		{
			Desc: "unknown user",
			Err: &hubauth.OAuthError{
				Code:        "access_denied",
				Description: "unknown user",
			},
			UserID: "unknown",
		},
		{
			Desc:   "valid user",
			Err:    nil,
			UserID: validUserID,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.Desc, func(t *testing.T) {
			err := s.VerifyUserGroups(context.Background(), testCase.UserID)
			if testCase.Err != nil {
				require.Equal(t, testCase.Err, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestAllocateRefreshToken(t *testing.T) {
	s := newTestSteps(t)

	t.Run("allocate reserves a refresh token id", func(t *testing.T) {
		clientID, err := s.db.CreateClient(context.Background(), &hubauth.Client{})
		require.NoError(t, err)

		rtID, err := s.AllocateRefreshToken(context.Background(), clientID)
		require.NoError(t, err)
		require.NotEmpty(t, rtID)

		codeID, _, err := s.db.CreateCode(context.Background(), &hubauth.Code{
			ClientID: clientID,
		})
		require.NoError(t, err)
		createdRtID, err := s.db.CreateRefreshToken(context.Background(), &hubauth.RefreshToken{
			ID:       rtID,
			CodeID:   codeID,
			ClientID: clientID,
		})

		require.NoError(t, err)
		require.Equal(t, rtID, createdRtID)
	})

	t.Run("allocate doesn't reserve id with invalid clientID", func(t *testing.T) {
		rtID, err := s.AllocateRefreshToken(context.Background(), "invalid")
		require.Error(t, err)
		require.Empty(t, rtID)
	})
}

func TestSaveRefreshToken(t *testing.T) {
	s := newTestSteps(t)

	rtExpiry := 60 * time.Second
	clientID, err := s.db.CreateClient(context.Background(), &hubauth.Client{
		RefreshTokenExpiry: rtExpiry,
	})
	require.NoError(t, err)

	rtID, err := s.AllocateRefreshToken(context.Background(), clientID)
	require.NoError(t, err)
	require.NotEmpty(t, rtID)

	codeID, _, err := s.db.CreateCode(context.Background(), &hubauth.Code{
		ClientID: clientID,
	})
	require.NoError(t, err)

	rtData := &refreshTokenData{
		Key:       rtID,
		IssueTime: time.Now(),
		UserID:    "userID",
		UserEmail: "userEmail",
		ClientID:  clientID,
	}

	redirectURI := "redirectURI"

	c, err := s.SaveRefreshToken(context.Background(), codeID, redirectURI, rtData)
	require.NoError(t, err)
	require.Equal(t, c.ID, clientID)

	rt, err := s.db.GetRefreshToken(context.Background(), rtID)
	require.NoError(t, err)

	require.Equal(t, rt.ID, rtID)
	require.Equal(t, rt.ClientID, rtData.ClientID)
	require.Equal(t, rt.UserID, rtData.UserID)
	require.Equal(t, rt.UserEmail, rtData.UserEmail)
	require.Equal(t, rt.RedirectURI, redirectURI)
	require.Equal(t, rt.CodeID, codeID)
	require.Equal(t, rt.IssueTime.Truncate(time.Millisecond), rtData.IssueTime.Truncate(time.Millisecond))
	require.Equal(t, rt.ExpiryTime.Truncate(time.Millisecond), rtData.IssueTime.Add(rtExpiry).Truncate(time.Millisecond))
}

func TestSaveRefreshTokenErrors(t *testing.T) {
	s := newTestSteps(t)

	testCases := []struct {
		Desc   string
		Err    error
		RtData *refreshTokenData
	}{
		{
			Desc: "unknown user",
			Err: &hubauth.OAuthError{
				Code:        "invalid_client",
				Description: "unknown client",
			},
			RtData: &refreshTokenData{
				ClientID: "unknown",
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.Desc, func(t *testing.T) {
			_, err := s.SaveRefreshToken(context.Background(), "codeID", "redirectURI", testCase.RtData)
			require.Equal(t, testCase.Err, err)
		})
	}
}

func TestSignRefreshToken(t *testing.T) {
	s := newTestSteps(t)

	signKeyName := "refreshKey"
	kms := kmssim.NewClient([]string{signKeyName})
	signKey, err := kmssign.NewKey(context.Background(), kms, signKeyName)
	require.NoError(t, err)

	now := time.Now()
	expireAt := now.Add(10 * time.Second)
	iss, _ := ptypes.TimestampProto(now)
	exp, _ := ptypes.TimestampProto(expireAt)

	keyBytes := []byte("rtKey")
	clientIDBytes := []byte("clientID")
	rt := &pb.RefreshToken{
		Key:        keyBytes,
		IssueTime:  iss,
		UserId:     "userID",
		UserEmail:  "userEmai",
		ClientId:   clientIDBytes,
		ExpireTime: exp,
	}

	rtData := &signedRefreshTokenData{
		refreshTokenData: &refreshTokenData{
			Key:       base64Encode(keyBytes),
			IssueTime: now,
			UserID:    rt.UserId,
			UserEmail: rt.UserEmail,
			ClientID:  base64Encode(clientIDBytes),
		},
		ExpiryTime: expireAt,
	}

	signedRT, err := s.SignRefreshToken(context.Background(), signKey, rtData)
	require.NoError(t, err)

	signedRTBytes, err := base64Decode(signedRT)
	require.NoError(t, err)

	gotRT := new(pb.RefreshToken)
	require.NoError(t, signpb.VerifyUnmarshal(signKey, signedRTBytes, gotRT))

	require.True(t, proto.Equal(rt, gotRT))
}

func TestSignRefreshTokenErrors(t *testing.T) {

	testCases := []struct {
		Desc        string
		RTData      *signedRefreshTokenData
		ErrContains string
	}{
		{
			Desc: "invalid b64 key",
			RTData: &signedRefreshTokenData{
				refreshTokenData: &refreshTokenData{
					Key: "not base64",
				},
			},
			ErrContains: "error decoding refresh token key",
		},
		{
			Desc: "invalid b64 clientID",
			RTData: &signedRefreshTokenData{
				refreshTokenData: &refreshTokenData{
					Key:      base64Encode([]byte("valid key")),
					ClientID: "not base64",
				},
			},
			ErrContains: "error decoding client id",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.Desc, func(t *testing.T) {
			s := newTestSteps(t)
			_, err := s.SignRefreshToken(context.Background(), nil, testCase.RTData)
			require.Error(t, err)
			require.Contains(t, err.Error(), testCase.ErrContains)
		})
	}
}

func TestRenewRefreshToken(t *testing.T) {
	s := newTestSteps(t)

	now := time.Now()
	oldRT := createTestRefreshToken(t, s.db, now)

	got, err := s.RenewRefreshToken(context.Background(), oldRT.ClientID, oldRT.ID, oldRT.IssueTime, now)
	require.NoError(t, err)

	require.NotEmpty(t, got.ID)
	require.Equal(t, oldRT.ID, got.ID)
	require.Equal(t, oldRT.ClientID, got.ClientID)
	require.NotEqual(t, oldRT.IssueTime, got.IssueTime)
	require.Equal(t, now.Truncate(time.Millisecond), got.IssueTime.Truncate(time.Millisecond))
	require.Equal(t, oldRT.UserID, got.UserID)
	require.Equal(t, oldRT.UserEmail, got.UserEmail)
	require.Equal(t, oldRT.RedirectURI, got.RedirectURI)
	require.Equal(t, oldRT.ExpiryTime.Truncate(time.Millisecond), got.ExpiryTime.Truncate(time.Millisecond))
}

func TestRenewRefreshTokenErrors(t *testing.T) {
	s := newTestSteps(t)
	now := time.Now()

	// Some errors may delete the refresh token, so we need several
	oldRT := createTestRefreshToken(t, s.db, now)
	oldRT2 := createTestRefreshToken(t, s.db, now)

	testCases := []struct {
		ClientID     string
		OldTokenID   string
		OldIssueTime time.Time
		Now          time.Time
		ExpectedErr  error
	}{
		{
			ClientID:     oldRT.ClientID,
			OldTokenID:   "unknown",
			OldIssueTime: oldRT.IssueTime,
			Now:          now,
			ExpectedErr: &hubauth.OAuthError{
				Code:        "invalid_grant",
				Description: "refresh_token not found",
			},
		},
		{
			ClientID:     oldRT.ClientID,
			OldTokenID:   oldRT.ID,
			OldIssueTime: oldRT.IssueTime,
			Now:          oldRT.ExpiryTime.Add(1 * time.Millisecond),
			ExpectedErr: &hubauth.OAuthError{
				Code:        "invalid_grant",
				Description: "refresh_token expired",
			},
		},
		{
			ClientID:     "invalid",
			OldTokenID:   oldRT.ID,
			OldIssueTime: oldRT.IssueTime,
			Now:          now,
			ExpectedErr: &hubauth.OAuthError{
				Code:        "invalid_grant",
				Description: "client_id mismatch",
			},
		},
		{
			ClientID:     oldRT2.ClientID,
			OldTokenID:   oldRT2.ID,
			OldIssueTime: oldRT2.IssueTime.Add(1 * time.Millisecond),
			Now:          now,
			ExpectedErr: &hubauth.OAuthError{
				Code:        "invalid_grant",
				Description: "unexpected refresh_token issue time",
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.ExpectedErr.Error(), func(t *testing.T) {
			_, err := s.RenewRefreshToken(context.Background(), testCase.ClientID, testCase.OldTokenID, testCase.OldIssueTime, testCase.Now)
			require.Equal(t, testCase.ExpectedErr, err)
		})
	}
}

func createTestRefreshToken(t *testing.T, db hubauth.DataStore, now time.Time) *hubauth.RefreshToken {
	clientID, err := db.CreateClient(context.Background(), &hubauth.Client{})
	require.NoError(t, err)

	codeID, _, err := db.CreateCode(context.Background(), &hubauth.Code{
		ClientID: clientID,
	})
	require.NoError(t, err)

	oldRT := &hubauth.RefreshToken{
		ClientID:    clientID,
		CodeID:      codeID,
		IssueTime:   now.Add(-10 * time.Second),
		UserID:      "userID",
		UserEmail:   "userEmail",
		RedirectURI: "redirectURI",
		ExpiryTime:  now.Add(10 * time.Second),
	}
	oldTokenID, err := db.CreateRefreshToken(context.Background(), oldRT)
	require.NoError(t, err)

	oldRT.ID = oldTokenID

	return oldRT
}

func TestVerifyRefreshToken(t *testing.T) {
	s := newTestSteps(t)

	now := time.Now()
	rt := createTestRefreshToken(t, s.db, now)

	require.NoError(t, s.VerifyRefreshToken(context.Background(), rt, now))
}

func TestVerifyRefreshTokenErrors(t *testing.T) {
	s := newTestSteps(t)

	now := time.Now()
	unknowRT := createTestRefreshToken(t, s.db, now)
	unknowRT.ID = "unknown"

	badIssueTime := createTestRefreshToken(t, s.db, now)
	badIssueTime.IssueTime = badIssueTime.IssueTime.Add(1 * time.Millisecond)

	expired := createTestRefreshToken(t, s.db, now)
	expiredTime := expired.ExpiryTime.Add(1 * time.Millisecond)

	testCases := []struct {
		RefreshToken *hubauth.RefreshToken
		Now          time.Time
		ExpectedErr  error
	}{
		{
			RefreshToken: unknowRT,
			Now:          now,
			ExpectedErr: &hubauth.OAuthError{
				Code:        "invalid_grant",
				Description: "refresh token not found",
			},
		},
		{
			RefreshToken: badIssueTime,
			Now:          now,
			ExpectedErr: &hubauth.OAuthError{
				Code:        "invalid_grant",
				Description: "unexpected refresh token issue time",
			},
		},
		{
			RefreshToken: expired,
			Now:          expiredTime,
			ExpectedErr: &hubauth.OAuthError{
				Code:        "invalid_grant",
				Description: "refresh_token expired",
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.ExpectedErr.Error(), func(t *testing.T) {
			err := s.VerifyRefreshToken(context.Background(), testCase.RefreshToken, testCase.Now)
			require.Equal(t, testCase.ExpectedErr, err)
		})
	}
}

func TestSignAccessToken(t *testing.T) {
	s := newTestSteps(t)

	signKeyName := "refreshKey"
	kms := kmssim.NewClient([]string{signKeyName})
	signKey, err := kmssign.NewKey(context.Background(), kms, signKeyName)
	require.NoError(t, err)

	now := time.Now()
	data := &accessTokenData{
		clientID:  "clientID",
		userID:    "userID",
		userEmail: "userEmail",
	}

	accessToken, err := s.SignAccessToken(context.Background(), signKey, data, now)
	require.NoError(t, err)

	require.NotEmpty(t, accessToken)

	got := new(pb.AccessToken)

	accessTokenBytes, err := base64Decode(accessToken)
	require.NoError(t, err)

	require.NoError(t, signpb.VerifyUnmarshal(signKey, accessTokenBytes, got))
	require.Equal(t, data.clientID, got.ClientId)
	require.Equal(t, data.userID, got.UserId)
	require.Equal(t, data.userEmail, got.UserEmail)

	nowPb, _ := ptypes.TimestampProto(now)
	require.Equal(t, nowPb, got.IssueTime)

	expirePb, _ := ptypes.TimestampProto(now.Add(accessTokenDuration))
	require.Equal(t, expirePb, got.ExpireTime)
}
