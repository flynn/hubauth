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
	kmspb "google.golang.org/genproto/googleapis/cloud/kms/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type mockKMS struct {
	mock.Mock
}

func (m *mockKMS) CreateCryptoKey(ctx context.Context, req *kmspb.CreateCryptoKeyRequest, opts ...gax.CallOption) (*kmspb.CryptoKey, error) {
	// opts ignored, testify mocks doesn't seems to really like variadic args...
	args := m.Called(ctx, req)
	return args.Get(0).(*kmspb.CryptoKey), args.Error(1)
}
func (m *mockKMS) GetPublicKey(ctx context.Context, req *kmspb.GetPublicKeyRequest, opts ...gax.CallOption) (*kmspb.PublicKey, error) {
	// opts ignored, testify mocks doesn't seems to really like variadic args...
	args := m.Called(ctx, req)
	return args.Get(0).(*kmspb.PublicKey), args.Error(1)
}
func (m *mockKMS) ListCryptoKeyVersions(ctx context.Context, req *kmspb.ListCryptoKeyVersionsRequest, opts ...gax.CallOption) ([]*kmspb.CryptoKeyVersion, error) {
	args := m.Called(ctx, req)
	return args.Get(0).([]*kmspb.CryptoKeyVersion), args.Error(1)
}
func (m *mockKMS) DestroyCryptoKeyVersion(ctx context.Context, req *kmspb.DestroyCryptoKeyVersionRequest, opts ...gax.CallOption) (*kmspb.CryptoKeyVersion, error) {
	args := m.Called(ctx, req)
	return args.Get(0).(*kmspb.CryptoKeyVersion), args.Error(1)
}
func (m *mockKMS) CreateCryptoKeyVersion(ctx context.Context, req *kmspb.CreateCryptoKeyVersionRequest, opts ...gax.CallOption) (*kmspb.CryptoKeyVersion, error) {
	args := m.Called(ctx, req)
	return args.Get(0).(*kmspb.CryptoKeyVersion), args.Error(1)
}
func (m *mockKMS) RestoreCryptoKeyVersion(ctx context.Context, req *kmspb.RestoreCryptoKeyVersionRequest, opts ...gax.CallOption) (*kmspb.CryptoKeyVersion, error) {
	args := m.Called(ctx, req)
	return args.Get(0).(*kmspb.CryptoKeyVersion), args.Error(1)
}
func (m *mockKMS) UpdateCryptoKeyVersion(ctx context.Context, req *kmspb.UpdateCryptoKeyVersionRequest, opts ...gax.CallOption) (*kmspb.CryptoKeyVersion, error) {
	args := m.Called(ctx, req)
	return args.Get(0).(*kmspb.CryptoKeyVersion), args.Error(1)
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
func (m *mockAudienceDatastore) GetAudience(ctx context.Context, url string) (*hubauth.Audience, error) {
	args := m.Called(ctx, url)
	return args.Get(0).(*hubauth.Audience), args.Error(1)
}
func (m *mockAudienceDatastore) CreateAudience(ctx context.Context, audience *hubauth.Audience) error {
	args := m.Called(ctx, audience)
	return args.Error(0)
}
func (m *mockAudienceDatastore) DeleteAudience(ctx context.Context, url string) error {
	args := m.Called(ctx, url)
	return args.Error(0)
}
func (m *mockAudienceDatastore) MutateAudience(ctx context.Context, url string, mut []*hubauth.AudienceMutation) error {
	args := m.Called(ctx, url, mut)
	return args.Error(0)
}

func (m *mockAudienceDatastore) MutateAudiencePolicy(ctx context.Context, url string, domain string, mut []*hubauth.AudiencePolicyMutation) error {
	args := m.Called(ctx, url, domain, mut)
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
			Type:       "type1",
			ClientIDs:  []string{"client1", "client2"},
			CreateTime: createTime,
			UpdateTime: updateTime,
		},
		{
			URL:        "audience2URL",
			Type:       "type2",
			ClientIDs:  []string{"client3"},
			CreateTime: createTime,
			UpdateTime: updateTime,
		},
		{
			URL:        "audience3URL",
			Type:       "type3",
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
	tw.AppendHeader(table.Row{"URL", "Type", "ClientIDs", "CreateTime", "UpdateTime"})
	for _, a := range audiences {
		tw.AppendRow(table.Row{a.URL, a.Type, a.ClientIDs, a.CreateTime, a.UpdateTime})
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
		Type:        "flynn_controller",
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
	cfg.KMS.(*mockKMS).On("CreateCryptoKey", mock.Anything, &kmspb.CreateCryptoKeyRequest{
		Parent:      fmt.Sprintf("projects/%s/locations/%s/keyRings/%s", cfg.ProjectID, cmd.KMSLocation, cmd.KMSKeyring),
		CryptoKeyId: "audience_url_com",
		CryptoKey: &kmspb.CryptoKey{
			Purpose: kmspb.CryptoKey_ASYMMETRIC_SIGN,
			VersionTemplate: &kmspb.CryptoKeyVersionTemplate{
				ProtectionLevel: kmspb.ProtectionLevel_SOFTWARE,
				Algorithm:       kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256,
			},
		},
	}).Return(&kmspb.CryptoKey{}, nil)

	cfg.DB.(*mockAudienceDatastore).On("CreateAudience", mock.Anything, &hubauth.Audience{
		URL:       "https://audience.url.com",
		Type:      "flynn_controller",
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
			cfg.KMS.(*mockKMS).On("CreateCryptoKey", mock.Anything, mock.Anything).Return(&kmspb.CryptoKey{}, testCase.CreateCryptoKeyErr)
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
		KeyVersion:  2,
	}

	cfg := &Config{
		DB:        &mockAudienceDatastore{},
		KMS:       &mockKMS{},
		ProjectID: "projectID",
	}

	expectedKeyVersion, err := cryptoKeyVersion(cfg.ProjectID, cmd.KMSLocation, cmd.KMSKeyring, cmd.URL, 2)
	require.NoError(t, err)

	cfg.DB.(*mockAudienceDatastore).On("GetAudience", mock.Anything, cmd.URL).Return(&hubauth.Audience{
		URL: cmd.URL,
	}, nil)

	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	pubKeyDER, err := x509.MarshalPKIXPublicKey(privKey.Public())
	require.NoError(t, err)
	pubKeyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubKeyDER}))
	expectedPublicKey := &kmspb.PublicKey{Pem: pubKeyPEM}

	cfg.KMS.(*mockKMS).On("GetPublicKey", mock.Anything, &kmspb.GetPublicKeyRequest{Name: expectedKeyVersion}).Return(expectedPublicKey, nil)

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

			cfg.KMS.(*mockKMS).On("GetPublicKey", mock.Anything, mock.Anything).Return(&kmspb.PublicKey{}, testCase.GetPublicKeyErr)

			err := cmd.Run(cfg)
			if testCase.ExpectedErr != nil {
				require.Equal(t, testCase.ExpectedErr, errors.Unwrap(err))
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
		AudienceURL:   "https://audience.url",
		AddClients:    []string{"client1", "client2"},
		DeleteClients: []string{"client3"},
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

func TestAudienceDeleteCmd(t *testing.T) {
	cmd := &audiencesDeleteCmd{
		AudienceURL: "https://removed.audience.url",
		KMSLocation: "global",
		KMSKeyring:  "keyring",
	}

	cfg := &Config{
		DB:        &mockAudienceDatastore{},
		KMS:       &mockKMS{},
		ProjectID: "projectID",
	}

	versions := []*kmspb.CryptoKeyVersion{{Name: "v1"}, {Name: "v2"}}

	expectedKeyName, err := cryptoKeyName(cfg.ProjectID, cmd.KMSLocation, cmd.KMSKeyring, cmd.AudienceURL)
	require.NoError(t, err)

	cfg.KMS.(*mockKMS).On("ListCryptoKeyVersions", mock.Anything, &kmspb.ListCryptoKeyVersionsRequest{
		Parent: expectedKeyName,
	}).Return(versions, nil)

	cfg.KMS.(*mockKMS).On("DestroyCryptoKeyVersion", mock.Anything, &kms.DestroyCryptoKeyVersionRequest{Name: "v1"}).Once().Return(&kmspb.CryptoKeyVersion{}, nil)
	cfg.KMS.(*mockKMS).On("DestroyCryptoKeyVersion", mock.Anything, &kms.DestroyCryptoKeyVersionRequest{Name: "v2"}).Once().Return(&kmspb.CryptoKeyVersion{}, nil)

	cfg.DB.(*mockAudienceDatastore).On("DeleteAudience", mock.Anything, cmd.AudienceURL).Return(nil)
	require.NoError(t, cmd.Run(cfg))
}

func TestAudienceDeleteErrors(t *testing.T) {
	testCases := []struct {
		Desc                       string
		AudienceURL                string
		ListCryptoKeyVersionsErr   error
		DestroyCryptoKeyVersionErr error
		DeleteAudienceErr          error
		ExpectedErr                error
	}{
		{
			Desc:        "audience url fail to parse",
			AudienceURL: "://audience.url",
		},
		{
			Desc:                     "fail to list keys",
			AudienceURL:              "https://audience.url",
			ListCryptoKeyVersionsErr: errors.New("list key versions error"),
			ExpectedErr:              errors.New("list key versions error"),
		},
		{
			Desc:                       "fail to destroy key",
			AudienceURL:                "https://audience.url",
			DestroyCryptoKeyVersionErr: errors.New("destroy key error"),
			ExpectedErr:                errors.New("destroy key error"),
		},
		{
			Desc:              "fail to delete audience",
			AudienceURL:       "https://audience.url",
			DeleteAudienceErr: errors.New("delete audience error"),
			ExpectedErr:       errors.New("delete audience error"),
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.Desc, func(t *testing.T) {
			cmd := &audiencesDeleteCmd{
				AudienceURL: testCase.AudienceURL,
				KMSLocation: "global",
				KMSKeyring:  "keyring",
			}

			cfg := &Config{
				DB:        &mockAudienceDatastore{},
				KMS:       &mockKMS{},
				ProjectID: "projectID",
			}

			cfg.KMS.(*mockKMS).On("ListCryptoKeyVersions", mock.Anything, mock.Anything).Return([]*kmspb.CryptoKeyVersion{{Name: "v1"}}, testCase.ListCryptoKeyVersionsErr)
			cfg.KMS.(*mockKMS).On("DestroyCryptoKeyVersion", mock.Anything, mock.Anything).Return(&kmspb.CryptoKeyVersion{}, testCase.DestroyCryptoKeyVersionErr)

			cfg.DB.(*mockAudienceDatastore).On("DeleteAudience", mock.Anything, cmd.AudienceURL).Return(testCase.DeleteAudienceErr)
			err := cmd.Run(cfg)
			if testCase.ExpectedErr != nil {
				require.Equal(t, testCase.ExpectedErr, errors.Unwrap(err))
			} else {
				require.Error(t, err)
			}
		})
	}
}

func TestAudienceListPolicies(t *testing.T) {
	cmd := &audiencesListPoliciesCmd{
		AudienceURL: "https://audience.url",
	}

	audience := &hubauth.Audience{
		Name: "https://audience.url",
		Policies: []*hubauth.GoogleUserPolicy{
			{
				APIUser: "user1",
				Domain:  "domain1",
				Groups:  []string{"grp1", "grp2"},
			},
			{
				APIUser: "user2",
				Domain:  "domain2",
				Groups:  []string{"grp3"},
			},
		},
	}

	cfg := &Config{
		DB: &mockAudienceDatastore{},
	}

	cfg.DB.(*mockAudienceDatastore).On("GetAudience", mock.Anything, cmd.AudienceURL).Return(audience, nil)

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
	tw.AppendHeader(table.Row{"Domain", "APIUser", "Groups"})
	for _, p := range audience.Policies {
		tw.AppendRow(table.Row{p.Domain, p.APIUser, p.Groups})
	}
	tw.Render()

	require.Equal(t, expectedBuf.String(), string(buf[:n]))
}

func TestAudienceListPoliciesError(t *testing.T) {
	cmd := &audiencesListPoliciesCmd{
		AudienceURL: "https://audience.url",
	}

	cfg := &Config{
		DB: &mockAudienceDatastore{},
	}

	expectedErr := errors.New("audience list error")
	cfg.DB.(*mockAudienceDatastore).On("GetAudience", mock.Anything, cmd.AudienceURL).Return(&hubauth.Audience{}, expectedErr)
	require.Equal(t, expectedErr, cmd.Run(cfg))
}

func TestAudienceUpdatePolicyCmd(t *testing.T) {
	cmd := &audiencesUpdatePolicyCmd{
		AudienceURL:  "https://modified.audience.url",
		Domain:       "policy.domain",
		APIUser:      "user1",
		AddGroups:    []string{"grp1", "grp2"},
		DeleteGroups: []string{"grp3", "grp4"},
	}

	cfg := &Config{
		DB: &mockAudienceDatastore{},
	}

	muts := []*hubauth.AudiencePolicyMutation{
		{
			Op:    hubauth.AudiencePolicyMutationOpAddGroup,
			Group: "grp1",
		},
		{
			Op:    hubauth.AudiencePolicyMutationOpAddGroup,
			Group: "grp2",
		},
		{
			Op:    hubauth.AudiencePolicyMutationOpDeleteGroup,
			Group: "grp3",
		},
		{
			Op:    hubauth.AudiencePolicyMutationOpDeleteGroup,
			Group: "grp4",
		},
		{
			Op:      hubauth.AudiencePolicyMutationOpSetAPIUser,
			APIUser: "user1",
		},
	}

	cfg.DB.(*mockAudienceDatastore).On("MutateAudiencePolicy", mock.Anything, cmd.AudienceURL, cmd.Domain, muts).Return(nil)

	require.NoError(t, cmd.Run(cfg))
}

func TestAudienceUpdateTypeCmd(t *testing.T) {
	cmd := &audienceUpdateTypeCmd{
		AudienceURL:  "https://modified.audience.url",
		AudienceType: "new-type",
	}

	cfg := &Config{
		DB: &mockAudienceDatastore{},
	}
	muts := []*hubauth.AudienceMutation{{
		Op:   hubauth.AudienceMutationOpSetType,
		Type: cmd.AudienceType,
	}}

	cfg.DB.(*mockAudienceDatastore).On("MutateAudience", mock.Anything, cmd.AudienceURL, muts).Return(nil)

	require.NoError(t, cmd.Run(cfg))
}

func TestAudiencesListKeyVersionsCmd(t *testing.T) {
	cmd := &audiencesListKeyVersionsCmd{
		URL:         "https://audience.url",
		KMSKeyring:  "keyring",
		KMSLocation: "location",
	}

	cfg := &Config{
		KMS:       &mockKMS{},
		ProjectID: "project-id",
	}

	keyName, err := cryptoKeyName(cfg.ProjectID, cmd.KMSLocation, cmd.KMSKeyring, cmd.URL)
	require.NoError(t, err)

	now := time.Now()
	versions := []*kmspb.CryptoKeyVersion{
		{
			Name:       "resource/name/1",
			State:      kms.CryptoKeyVersion_ENABLED,
			Algorithm:  kms.CryptoKeyVersion_EC_SIGN_P256_SHA256,
			CreateTime: timestamppb.New(now.Add(-5 * time.Minute)),
		},
		{
			Name:        "resource/name/2",
			State:       kms.CryptoKeyVersion_DESTROY_SCHEDULED,
			Algorithm:   kms.CryptoKeyVersion_EC_SIGN_P384_SHA384,
			CreateTime:  timestamppb.New(now.Add(-10 * time.Second)),
			DestroyTime: timestamppb.New(now),
		},
	}

	cfg.KMS.(*mockKMS).On("ListCryptoKeyVersions", mock.Anything, &kms.ListCryptoKeyVersionsRequest{
		Parent: keyName,
	}).Return(versions, nil)

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
	tw.AppendHeader(table.Row{"Version", "State", "Alg", "CreateTime", "DestroyTime"})
	tw.AppendRow(table.Row{"1", kmspb.CryptoKeyVersion_ENABLED, kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256, timestamppb.New(now.Add(-5 * time.Minute)).AsTime(), ""})
	tw.AppendRow(table.Row{"2", kmspb.CryptoKeyVersion_DESTROY_SCHEDULED, kmspb.CryptoKeyVersion_EC_SIGN_P384_SHA384, timestamppb.New(now.Add(-10 * time.Second)).AsTime(), timestamppb.New(now).AsTime()})
	tw.Render()

	require.Equal(t, expectedBuf.String(), string(buf[:n]))
}

func TestAudiencesListKeyVersionsErrors(t *testing.T) {
	testCases := []struct {
		Desc                     string
		AudienceURL              string
		ListCryptoKeyVersionsErr error
		ExpectedErr              error
	}{
		{
			Desc:        "audience url fail to parse",
			AudienceURL: "://audience.url",
		},
		{
			Desc:                     "fail to list keys",
			AudienceURL:              "https://audience.url",
			ListCryptoKeyVersionsErr: errors.New("list key versions error"),
			ExpectedErr:              errors.New("list key versions error"),
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.Desc, func(t *testing.T) {
			cmd := &audiencesListKeyVersionsCmd{
				URL:         testCase.AudienceURL,
				KMSLocation: "global",
				KMSKeyring:  "keyring",
			}

			cfg := &Config{
				KMS:       &mockKMS{},
				ProjectID: "projectID",
			}

			cfg.KMS.(*mockKMS).On("ListCryptoKeyVersions", mock.Anything, mock.Anything).Return([]*kmspb.CryptoKeyVersion{{Name: "v1"}}, testCase.ListCryptoKeyVersionsErr)
			err := cmd.Run(cfg)
			if testCase.ExpectedErr != nil {
				require.Equal(t, testCase.ExpectedErr, errors.Unwrap(err))
			} else {
				require.Error(t, err)
			}
		})
	}
}
