package idp

import (
	"context"
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	gdatastore "cloud.google.com/go/datastore"
	"github.com/flynn/hubauth/pkg/datastore"
	"github.com/flynn/hubauth/pkg/hubauth"
	"github.com/stretchr/testify/require"
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
	require.EqualError(t, err, hubauth.OAuthError{
		Code:        "invalid_grant",
		Description: "code is malformed or has already been exchanged",
	}.Error())
	require.Equal(t, codeID, got.ID)

	_, err = s.db.GetRefreshToken(context.Background(), rtID)
	require.EqualError(t, errors.Unwrap(err), hubauth.ErrNotFound.Error())

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
			require.EqualError(t, err, testCase.Err.Error())
		})
	}
}
