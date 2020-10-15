package cli

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/flynn/hubauth/pkg/hubauth"
	"github.com/googleapis/gax-go/v2"
	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"google.golang.org/genproto/googleapis/cloud/kms/v1"
)

type mockKMS struct {
	mock.Mock
}

func (m *mockKMS) CreateCryptoKey(ctx context.Context, req *kms.CreateCryptoKeyRequest, opts ...gax.CallOption) (*kms.CryptoKey, error) {
	// opts ignored, testify mocks doesn't seems to really like variadic args...
	args := m.Called(ctx, req)
	return args.Get(0).(*kms.CryptoKey), args.Error(1)
}
func (m *mockKMS) GetPublicKey(ctx context.Context, req *kms.GetPublicKeyRequest, opts ...gax.CallOption) (*kms.PublicKey, error) {
	// opts ignored, testify mocks doesn't seems to really like variadic args...
	args := m.Called(ctx, req)
	return args.Get(0).(*kms.PublicKey), args.Error(1)
}

type mockAudienceDatastore struct {
	mock.Mock
	hubauth.DataStore
}

func (m *mockAudienceDatastore) ListAudiences(ctx context.Context) ([]*hubauth.Audience, error) {
	args := m.Called(ctx)
	return args.Get(0).([]*hubauth.Audience), args.Error(1)
}
func (m *mockAudienceDatastore) GetClient(ctx context.Context, id string) (*hubauth.Client, error) {
	args := m.Called(ctx, id)
	return args.Get(0).(*hubauth.Client), args.Error(1)

}
func (m *mockAudienceDatastore) CreateAudience(ctx context.Context, audience *hubauth.Audience) error {
	args := m.Called(ctx, audience)
	return args.Error(0)
}
func (m *mockAudienceDatastore) MutateAudience(ctx context.Context, url string, mut []*hubauth.AudienceMutation) error {
	args := m.Called(ctx, url, mut)
	return args.Error(0)
}

func TestAudiencesListCmd(t *testing.T) {
	cmd := &audiencesListCmd{}
	cfg := &Config{
		DB:        &mockAudienceDatastore{},
		KMS:       &mockKMS{},
		ProjectID: "projectID",
	}

	createTime := time.Now().Add(-5 * time.Second)
	updateTime := time.Now()

	audiences := []*hubauth.Audience{
		{
			URL:        "audience1URL",
			ClientIDs:  []string{"client1", "client2"},
			CreateTime: createTime,
			UpdateTime: updateTime,
		},
		{
			URL:        "audience2URL",
			ClientIDs:  []string{"client3"},
			CreateTime: createTime,
			UpdateTime: updateTime,
		},
		{
			URL:        "audience3URL",
			ClientIDs:  []string{},
			CreateTime: createTime,
			UpdateTime: updateTime,
		},
	}

	cfg.DB.(*mockAudienceDatastore).On("ListAudiences", mock.Anything).Return(audiences, nil)

	r, w, err := os.Pipe()
	require.NoError(t, err)
	origStdout := os.Stdout
	os.Stdout = w

	require.NoError(t, cmd.Run(cfg))

	os.Stdout = origStdout
	buf := make([]byte, 2048)
	n, err := r.Read(buf)
	require.NoError(t, err)

	expectedBuf := new(bytes.Buffer)
	tw := table.NewWriter()
	tw.SetOutputMirror(expectedBuf)
	tw.AppendHeader(table.Row{"URL", "ClientIDs", "CreateTime", "UpdateTime"})
	for _, a := range audiences {
		tw.AppendRow(table.Row{a.URL, a.ClientIDs, a.CreateTime, a.UpdateTime})
	}
	tw.Render()

	require.Equal(t, expectedBuf.String(), string(buf[:n]))
}

func TestAudienceListErrors(t *testing.T) {
	cmd := &audiencesListCmd{}
	cfg := &Config{
		DB:        &mockAudienceDatastore{},
		KMS:       &mockKMS{},
		ProjectID: "projectID",
	}

	expectedErr := errors.New("audience list error")

	cfg.DB.(*mockAudienceDatastore).On("ListAudiences", mock.Anything).Return([]*hubauth.Audience{}, expectedErr)

	require.Equal(t, expectedErr, cmd.Run(cfg))
}

func TestAudienceCreateCmd(t *testing.T) {
	cmd := &audiencesCreateCmd{
		URL:         "https://audience.url.com",
		ClientIDs:   []string{"client1", "client2"},
		KMSLocation: "kmsLocation",
		KMSKeyring:  "kmsKeyring",
	}
	cfg := &Config{
		DB:        &mockAudienceDatastore{},
		KMS:       &mockKMS{},
		ProjectID: "projectID",
	}

	cfg.DB.(*mockAudienceDatastore).On("GetClient", mock.Anything, "client1").Return(&hubauth.Client{}, nil)
	cfg.DB.(*mockAudienceDatastore).On("GetClient", mock.Anything, "client2").Return(&hubauth.Client{}, nil)
	cfg.KMS.(*mockKMS).On("CreateCryptoKey", mock.Anything, &kms.CreateCryptoKeyRequest{
		Parent:      fmt.Sprintf("projects/%s/locations/%s/keyRings/%s", cfg.ProjectID, cmd.KMSLocation, cmd.KMSKeyring),
		CryptoKeyId: "audience_url_com",
		CryptoKey: &kms.CryptoKey{
			Purpose: kms.CryptoKey_ASYMMETRIC_SIGN,
			VersionTemplate: &kms.CryptoKeyVersionTemplate{
				ProtectionLevel: kms.ProtectionLevel_SOFTWARE,
				Algorithm:       kms.CryptoKeyVersion_EC_SIGN_P256_SHA256,
			},
		},
	}).Return(&kms.CryptoKey{}, nil)

	cfg.DB.(*mockAudienceDatastore).On("CreateAudience", mock.Anything, &hubauth.Audience{
		URL:       "https://audience.url.com",
		ClientIDs: cmd.ClientIDs,
	}).Return(nil)

	require.NoError(t, cmd.Run(cfg))
}

func TestAudienceCreateErrors(t *testing.T) {
	testCases := []struct {
		Desc               string
		GetClientErr       error
		CreateCryptoKeyErr error
		CreateAudienceErr  error
		ExpectedErr        error
		AudienceURL        string
		NeedsUnwrap        bool
	}{
		{
			Desc:         "fail to verify clientIDs",
			GetClientErr: errors.New("get client error"),
			ExpectedErr:  errors.New("get client error"),
		},
		{
			Desc:        "audience url fail to parse",
			AudienceURL: "://audience.url",
		},
		{
			Desc:        "audience url no https",
			AudienceURL: "http://audience.url",
		},
		{
			Desc:        "audience url path not empty",
			AudienceURL: "https://audience.url/path",
		},
		{
			Desc:               "fail to create crypto key",
			AudienceURL:        "https://audience.url",
			CreateCryptoKeyErr: errors.New("create crypto key error"),
			ExpectedErr:        errors.New("create crypto key error"),
			NeedsUnwrap:        true,
		},
		{
			Desc:              "fail to create audience",
			AudienceURL:       "https://audience.url",
			CreateAudienceErr: errors.New("create audience error"),
			ExpectedErr:       errors.New("create audience error"),
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.Desc, func(t *testing.T) {
			cmd := &audiencesCreateCmd{
				URL:         testCase.AudienceURL,
				ClientIDs:   []string{"client1", "client2"},
				KMSLocation: "kmsLocation",
				KMSKeyring:  "kmsKeyring",
			}
			cfg := &Config{
				DB:        &mockAudienceDatastore{},
				KMS:       &mockKMS{},
				ProjectID: "projectID",
			}

			cfg.DB.(*mockAudienceDatastore).On("GetClient", mock.Anything, mock.Anything).Return(&hubauth.Client{}, testCase.GetClientErr)
			cfg.KMS.(*mockKMS).On("CreateCryptoKey", mock.Anything, mock.Anything).Return(&kms.CryptoKey{}, testCase.CreateCryptoKeyErr)
			cfg.DB.(*mockAudienceDatastore).On("CreateAudience", mock.Anything, mock.Anything).Return(testCase.CreateAudienceErr)

			err := cmd.Run(cfg)
			if testCase.NeedsUnwrap {
				err = errors.Unwrap(err)
			}

			if testCase.ExpectedErr != nil {
				require.Equal(t, testCase.ExpectedErr, err)
			} else {
				require.Error(t, err)
			}
		})
	}
}

func TestAudienceSetPolicyCmd(t *testing.T) {
	cmd := &audiencesSetPolicyCmd{
		APIUser:     "apiUser",
		AudienceURL: "https://audience.url",
		Domain:      "domain",
		Groups:      []string{"group1", "group2"},
	}

	cfg := &Config{
		DB:        &mockAudienceDatastore{},
		KMS:       &mockKMS{},
		ProjectID: "projectID",
	}

	muts := []*hubauth.AudienceMutation{
		{
			Op: hubauth.AudienceMutationOpSetPolicy,
			Policy: hubauth.GoogleUserPolicy{
				Domain:  cmd.Domain,
				APIUser: cmd.APIUser,
				Groups:  cmd.Groups,
			},
		},
	}

	cfg.DB.(*mockAudienceDatastore).On("MutateAudience", mock.Anything, cmd.AudienceURL, muts).Return(nil)

	require.NoError(t, cmd.Run(cfg))
}

func TestAudienceSetPolicyErrors(t *testing.T) {
	cmd := &audiencesSetPolicyCmd{
		APIUser:     "apiUser",
		AudienceURL: "https://audience.url",
		Domain:      "domain",
		Groups:      []string{"group1", "group2"},
	}

	expectedErr := errors.New("mutate audience error")

	cfg := &Config{
		DB:        &mockAudienceDatastore{},
		KMS:       &mockKMS{},
		ProjectID: "projectID",
	}

	cfg.DB.(*mockAudienceDatastore).On("MutateAudience", mock.Anything, mock.Anything, mock.Anything).Return(expectedErr)

	require.Equal(t, expectedErr, cmd.Run(cfg))
}

func TestAudienceKeyCmd(t *testing.T) {
	cmd := &audiencesKeyCmd{
		KMSKeyring:  "kmsKeyring",
		KMSLocation: "kmsLocation",
		URL:         "https://audience.url",
	}

	cfg := &Config{
		DB:        &mockAudienceDatastore{},
		KMS:       &mockKMS{},
		ProjectID: "projectID",
	}

	expectedKeyName := fmt.Sprintf("projects/%s/locations/%s/keyRings/%s/cryptoKeys/%s/cryptoKeyVersions/1", cfg.ProjectID, cmd.KMSLocation, cmd.KMSKeyring, "audience_url")

	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	pubKeyDER, err := x509.MarshalPKIXPublicKey(privKey.Public())
	require.NoError(t, err)
	pubKeyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubKeyDER}))
	expectedPublicKey := &kms.PublicKey{Pem: pubKeyPEM}

	cfg.KMS.(*mockKMS).On("GetPublicKey", mock.Anything, &kms.GetPublicKeyRequest{Name: expectedKeyName}).Return(expectedPublicKey, nil)

	r, w, err := os.Pipe()
	require.NoError(t, err)
	origStdout := os.Stdout
	os.Stdout = w

	require.NoError(t, cmd.Run(cfg))

	os.Stdout = origStdout

	buf := make([]byte, 2048)
	n, err := r.Read(buf)
	require.NoError(t, err)

	expectedOut := fmt.Sprintf("%s\n", base64.URLEncoding.EncodeToString(pubKeyDER))
	require.Equal(t, expectedOut, string(buf[:n]))
}

func TestAudienceKeyErrors(t *testing.T) {
	testCases := []struct {
		Desc            string
		GetPublicKeyErr error
		ExpectedErr     error
		AudienceURL     string
	}{
		{
			Desc:        "audience url fail to parse",
			AudienceURL: "://audience.url",
		},
		{
			Desc:        "audience url no https",
			AudienceURL: "http://audience.url",
		},
		{
			Desc:        "audience url path not empty",
			AudienceURL: "https://audience.url/path",
		},
		{
			Desc:            "fail to get public key",
			AudienceURL:     "https://audience.url",
			GetPublicKeyErr: errors.New("get public key error"),
			ExpectedErr:     errors.New("get public key error"),
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.Desc, func(t *testing.T) {
			cmd := &audiencesKeyCmd{
				URL:         testCase.AudienceURL,
				KMSLocation: "kmsLocation",
				KMSKeyring:  "kmsKeyring",
			}
			cfg := &Config{
				DB:        &mockAudienceDatastore{},
				KMS:       &mockKMS{},
				ProjectID: "projectID",
			}

			cfg.KMS.(*mockKMS).On("GetPublicKey", mock.Anything, mock.Anything).Return(&kms.PublicKey{}, testCase.GetPublicKeyErr)

			err := cmd.Run(cfg)
			if testCase.ExpectedErr != nil {
				require.Equal(t, testCase.ExpectedErr, err)
			} else {
				require.Error(t, err)
			}
		})
	}
}

func TestAudienceDeletePolicyCmd(t *testing.T) {
	cmd := &audiencesDeletePolicyCmd{
		AudienceURL: "https://audience.url",
		Domain:      "domain",
	}

	cfg := &Config{
		DB: &mockAudienceDatastore{},
	}

	muts := []*hubauth.AudienceMutation{
		{
			Op: hubauth.AudienceMutationOpDeletePolicy,
			Policy: hubauth.GoogleUserPolicy{
				Domain: cmd.Domain,
			},
		},
	}

	cfg.DB.(*mockAudienceDatastore).On("MutateAudience", mock.Anything, cmd.AudienceURL, muts).Return(nil)

	require.NoError(t, cmd.Run(cfg))
}

func TestAudienceUpdateClientIDsCmd(t *testing.T) {
	cmd := &audiencesUpdateClientsIDsCmd{
		AudienceURL: "https://audience.url",
		Add:         []string{"client1", "client2"},
		Delete:      []string{"client3"},
	}

	cfg := &Config{
		DB: &mockAudienceDatastore{},
	}

	muts := []*hubauth.AudienceMutation{
		{
			Op:       hubauth.AudienceMutationOpAddClientID,
			ClientID: "client1",
		},
		{
			Op:       hubauth.AudienceMutationOpAddClientID,
			ClientID: "client2",
		},
		{
			Op:       hubauth.AudienceMutationOpDeleteClientID,
			ClientID: "client3",
		},
	}

	cfg.DB.(*mockAudienceDatastore).On("MutateAudience", mock.Anything, cmd.AudienceURL, muts).Return(nil)

	require.NoError(t, cmd.Run(cfg))
}
