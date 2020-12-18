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
	"io/ioutil"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/flynn/hubauth/pkg/hubauth"
	"github.com/flynn/hubauth/pkg/policy"
	"github.com/googleapis/gax-go/v2"
	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"google.golang.org/genproto/googleapis/cloud/kms/v1"
	kmspb "google.golang.org/genproto/googleapis/cloud/kms/v1"
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
func (m *mockAudienceDatastore) MutateAudiencePolicy(ctx context.Context, url string, policyName string, mut []*hubauth.AudiencePolicyMutation) error {
	args := m.Called(ctx, url, policyName, mut)
	return args.Error(0)
}
func (m *mockAudienceDatastore) MutateAudienceUserGroups(ctx context.Context, url string, domain string, mut []*hubauth.AudienceUserGroupsMutation) error {
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

func TestAudienceSetUserGroupsCmd(t *testing.T) {
	cmd := &audiencesSetUserGroupsCmd{
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
			Op: hubauth.AudienceMutationOpSetUserGroups,
			UserGroups: hubauth.GoogleUserGroups{
				Domain:  cmd.Domain,
				APIUser: cmd.APIUser,
				Groups:  cmd.Groups,
			},
		},
	}

	cfg.DB.(*mockAudienceDatastore).On("MutateAudience", mock.Anything, cmd.AudienceURL, muts).Return(nil)

	require.NoError(t, cmd.Run(cfg))
}

func TestAudienceSetUserGroupsErrors(t *testing.T) {
	cmd := &audiencesSetUserGroupsCmd{
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
	expectedPublicKey := &kmspb.PublicKey{Pem: pubKeyPEM}

	cfg.KMS.(*mockKMS).On("GetPublicKey", mock.Anything, &kmspb.GetPublicKeyRequest{Name: expectedKeyName}).Return(expectedPublicKey, nil)

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
				require.Equal(t, testCase.ExpectedErr, err)
			} else {
				require.Error(t, err)
			}
		})
	}
}

func TestAudienceDeleteUserGroupsCmd(t *testing.T) {
	cmd := &audiencesDeleteUserGroupsCmd{
		AudienceURL: "https://audience.url",
		Domain:      "domain",
	}

	cfg := &Config{
		DB: &mockAudienceDatastore{},
	}

	muts := []*hubauth.AudienceMutation{
		{
			Op: hubauth.AudienceMutationOpDeleteUserGroups,
			UserGroups: hubauth.GoogleUserGroups{
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

	cfg.KMS.(*mockKMS).On("ListCryptoKeyVersions", mock.Anything, &kmspb.ListCryptoKeyVersionsRequest{
		Parent: fmt.Sprintf("projects/%s/locations/%s/keyRings/%s/cryptoKeys/removed_audience_url",
			cfg.ProjectID,
			cmd.KMSLocation,
			cmd.KMSKeyring,
		),
	}).Return(versions, nil)

	cfg.KMS.(*mockKMS).On("DestroyCryptoKeyVersion", mock.Anything, &kms.DestroyCryptoKeyVersionRequest{Name: "v1"}).Once().Return(&kmspb.CryptoKeyVersion{}, nil)
	cfg.KMS.(*mockKMS).On("DestroyCryptoKeyVersion", mock.Anything, &kms.DestroyCryptoKeyVersionRequest{Name: "v2"}).Once().Return(&kmspb.CryptoKeyVersion{}, nil)

	cfg.DB.(*mockAudienceDatastore).On("DeleteAudience", mock.Anything, cmd.AudienceURL).Return(nil)
	require.NoError(t, cmd.Run(cfg))
}

func TestAudienceListUserGroups(t *testing.T) {
	cmd := &audiencesListUserGroupsCmd{
		AudienceURL: "https://audience.url",
	}

	audience := &hubauth.Audience{
		Name: "https://audience.url",
		UserGroups: []*hubauth.GoogleUserGroups{
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
	for _, ug := range audience.UserGroups {
		tw.AppendRow(table.Row{ug.Domain, ug.APIUser, ug.Groups})
	}
	tw.Render()

	require.Equal(t, expectedBuf.String(), string(buf[:n]))
}

func TestAudienceListUserGroupsError(t *testing.T) {
	cmd := &audiencesListUserGroupsCmd{
		AudienceURL: "https://audience.url",
	}

	cfg := &Config{
		DB: &mockAudienceDatastore{},
	}

	expectedErr := errors.New("audience list error")
	cfg.DB.(*mockAudienceDatastore).On("GetAudience", mock.Anything, cmd.AudienceURL).Return(&hubauth.Audience{}, expectedErr)
	require.Equal(t, expectedErr, cmd.Run(cfg))
}

func TestAudienceUpdateUserGroupsCmd(t *testing.T) {
	cmd := &audiencesUpdateUserGroupsCmd{
		AudienceURL:  "https://modified.audience.url",
		Domain:       "usergroups.domain",
		APIUser:      "user1",
		AddGroups:    []string{"grp1", "grp2"},
		DeleteGroups: []string{"grp3", "grp4"},
	}

	cfg := &Config{
		DB: &mockAudienceDatastore{},
	}

	muts := []*hubauth.AudienceUserGroupsMutation{
		{
			Op:    hubauth.AudienceUserGroupsMutationOpAddGroup,
			Group: "grp1",
		},
		{
			Op:    hubauth.AudienceUserGroupsMutationOpAddGroup,
			Group: "grp2",
		},
		{
			Op:    hubauth.AudienceUserGroupsMutationOpDeleteGroup,
			Group: "grp3",
		},
		{
			Op:    hubauth.AudienceUserGroupsMutationOpDeleteGroup,
			Group: "grp4",
		},
		{
			Op:      hubauth.AudienceUserGroupsMutationOpSetAPIUser,
			APIUser: "user1",
		},
	}

	cfg.DB.(*mockAudienceDatastore).On("MutateAudienceUserGroups", mock.Anything, cmd.AudienceURL, cmd.Domain, muts).Return(nil)

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
		Op:   hubauth.AudienceMutationSetType,
		Type: cmd.AudienceType,
	}}

	cfg.DB.(*mockAudienceDatastore).On("MutateAudience", mock.Anything, cmd.AudienceURL, muts).Return(nil)

	require.NoError(t, cmd.Run(cfg))
}

func TestAudienceListPoliciesCmd(t *testing.T) {
	cmd := &audiencesListPoliciesCmd{
		AudienceURL: "https://audience.url",
	}

	cfg := &Config{
		DB: &mockAudienceDatastore{},
	}

	policy1Content := "// policy1 description\npolicy \"policy1\" {}"
	policy2Content := "// policy2 description\npolicy \"policy2\" {}"
	policy3Content := "policy \"policy3\" {}"

	audience := &hubauth.Audience{
		URL: cmd.AudienceURL,
		Policies: []*hubauth.BiscuitPolicy{
			{
				Name:    "policy1",
				Content: policy1Content,
				Groups:  []string{"grp1", "grp2"},
			},
			{
				Name:    "policy2",
				Content: policy2Content,
				Groups:  nil,
			},
			{
				Name:    "policy3",
				Content: policy3Content,
				Groups:  nil,
			},
		},
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
	tw.AppendHeader(table.Row{"Name", "Groups", "Description"})
	for _, p := range audience.Policies {
		tw.AppendRow(table.Row{p.Name, p.Groups, getFirstComment(p)})
	}
	tw.Render()

	require.Equal(t, expectedBuf.String(), string(buf[:n]))
}

func TestAudiencesSetPoliciesCmd(t *testing.T) {
	policy1Content := `// policy1
policy "policy1" {
    rules {
        // rule1
        *r1($a) <- f1($a)
    }
}`

	policy2Content := `// policy2
policy "policy2" {}
`

	policyFile, err := ioutil.TempFile(os.TempDir(), "testaudiencessetpoliciescmd-")
	require.NoError(t, err)
	defer func() {
		policyFile.Close()
		os.Remove(policyFile.Name())
	}()

	_, err = policyFile.WriteString(policy1Content)
	require.NoError(t, err)
	_, err = policyFile.WriteString(policy2Content)
	require.NoError(t, err)

	groups := []string{"grp1", "grp2"}

	cmd := &audiencesSetPoliciesCmd{
		AudienceURL: "https://audience.url",
		Filepath:    policyFile.Name(),
		Groups:      groups,
	}

	cfg := &Config{
		DB: &mockAudienceDatastore{},
	}

	policy1ContentFmt, err := policy.Format(strings.NewReader(policy1Content))
	require.NoError(t, err)
	policy2ContentFmt, err := policy.Format(strings.NewReader(policy2Content))
	require.NoError(t, err)

	expectedMuts := []*hubauth.AudienceMutation{
		{
			Op: hubauth.AudienceMutationSetPolicy,
			Policy: hubauth.BiscuitPolicy{
				Name:    "policy1",
				Content: policy1ContentFmt,
				Groups:  groups,
			},
		},
		{
			Op: hubauth.AudienceMutationSetPolicy,
			Policy: hubauth.BiscuitPolicy{
				Name:    "policy2",
				Content: policy2ContentFmt,
				Groups:  groups,
			},
		},
	}

	cfg.DB.(*mockAudienceDatastore).On("MutateAudience", mock.Anything, cmd.AudienceURL, expectedMuts).Return(nil)

	require.NoError(t, cmd.Run(cfg))
}

func TestAudiencesUpdatePolicyCmd(t *testing.T) {
	policy1Content := "// policy1\npolicy \"policy1\" {}"

	policy1ContentFmt, err := policy.Format(strings.NewReader(policy1Content))
	require.NoError(t, err)

	policyFile, err := ioutil.TempFile(os.TempDir(), "testaudiencesupdatepoliciescmd-")
	require.NoError(t, err)
	defer func() {
		policyFile.Close()
		os.Remove(policyFile.Name())
	}()

	_, err = policyFile.WriteString(policy1Content)
	require.NoError(t, err)

	cmd := &audiencesUpdatePolicyCmd{
		AudienceURL:  "https://audience.url",
		PolicyName:   "policy1",
		Filepath:     policyFile.Name(),
		AddGroups:    []string{"grp1", "grp2"},
		DeleteGroups: []string{"grp3"},
	}

	cfg := &Config{
		DB: &mockAudienceDatastore{},
	}

	expectedMuts := []*hubauth.AudiencePolicyMutation{
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
			Op:      hubauth.AudiencePolicyMutationOpSetContent,
			Content: policy1ContentFmt,
		},
	}

	cfg.DB.(*mockAudienceDatastore).On("MutateAudiencePolicy", mock.Anything, cmd.AudienceURL, cmd.PolicyName, expectedMuts).Return(nil)

	require.NoError(t, cmd.Run(cfg))

	cmd.PolicyName = "not-existing-policy"
	require.Error(t, cmd.Run(cfg))
}

func TestAudiencesDeletePolicyCmd(t *testing.T) {
	cmd := audiencesDeletePolicyCmd{
		AudienceURL: "https://audience.url",
		PolicyName:  "policy1",
	}

	cfg := &Config{
		DB: &mockAudienceDatastore{},
	}

	expectedMuts := []*hubauth.AudienceMutation{
		{
			Op: hubauth.AudienceMutationDeletePolicy,
			Policy: hubauth.BiscuitPolicy{
				Name: cmd.PolicyName,
			},
		},
	}

	cfg.DB.(*mockAudienceDatastore).On("MutateAudience", mock.Anything, cmd.AudienceURL, expectedMuts).Return(nil)

	require.NoError(t, cmd.Run(cfg))
}

func TestAudiencesNewPolicyCmd(t *testing.T) {
	cmd := &audiencesNewPolicyCmd{}

	r, w, err := os.Pipe()
	require.NoError(t, err)
	origStdout := os.Stdout
	os.Stdout = w

	require.NoError(t, cmd.Run(&Config{}))

	os.Stdout = origStdout

	buf := make([]byte, 2048)
	n, err := r.Read(buf)
	require.NoError(t, err)

	policyTemplateFmt, err := policy.Format(strings.NewReader(policyTemplate))
	require.NoError(t, err)

	require.Equal(t, policyTemplateFmt, string(buf[:n]))

	policyFile, err := ioutil.TempFile(os.TempDir(), "testaudiencesnewpolicycmd-")
	require.NoError(t, err)
	defer func() {
		policyFile.Close()
		os.Remove(policyFile.Name())
	}()

	cmd.Filepath = policyFile.Name()
	require.NoError(t, cmd.Run(&Config{}))

	out, err := ioutil.ReadFile(policyFile.Name())
	require.NoError(t, err)
	require.Equal(t, policyTemplateFmt, string(out))
}

func TestAudiencesValidatePoliciesCmd(t *testing.T) {
	testCases := []struct {
		desc        string
		content     string
		expectValid bool
	}{
		{
			desc:        "valid policy",
			content:     `policy "p1" {}`,
			expectValid: true,
		},
		{
			desc:        "invalid policy",
			content:     `policy {}`,
			expectValid: false,
		},
		{
			desc:        "empty",
			content:     ``,
			expectValid: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			policyFile, err := ioutil.TempFile(os.TempDir(), "testaudiencesvalidatepolicycmd-")
			require.NoError(t, err)
			defer func() {
				policyFile.Close()
				os.Remove(policyFile.Name())
			}()

			_, err = policyFile.WriteString(tc.content)
			require.NoError(t, err)

			cmd := &audiencesValidatePoliciesCmd{
				Filepath: policyFile.Name(),
			}

			err = cmd.Run(&Config{})
			if tc.expectValid {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
			}
		})
	}
}

func TestAudiencesDumpPoliciesCmd(t *testing.T) {
	cmd := audiencesDumpPoliciesCmd{
		AudienceURL: "https://audience.url",
	}

	cfg := &Config{
		DB: &mockAudienceDatastore{},
	}

	p1Content := "policy \"p1\" {}"
	p2Content := "policy \"p2\" {}"
	p3Content := "policy \"p3\" {}"

	audience := &hubauth.Audience{
		URL: cmd.AudienceURL,
		Policies: []*hubauth.BiscuitPolicy{
			{
				Name:    "p1",
				Content: p1Content,
			},
			{
				Name:    "p2",
				Content: p2Content,
			},
			{
				Name:    "p3",
				Content: p3Content,
			},
		},
	}

	cfg.DB.(*mockAudienceDatastore).On("GetAudience", mock.Anything, cmd.AudienceURL).Return(audience, nil)

	r, w, err := os.Pipe()
	require.NoError(t, err)
	origStdout := os.Stdout
	os.Stdout = w

	require.NoError(t, cmd.Run(cfg))

	buf := make([]byte, 2048)
	n, err := r.Read(buf)
	require.NoError(t, err)
	require.Equal(t, strings.Join([]string{p1Content, p2Content, p3Content}, "\n\n")+"\n", string(buf[:n]))

	cmd.PolicyNames = []string{"p1", "p3"}
	require.NoError(t, cmd.Run(cfg))

	os.Stdout = origStdout

	n, err = r.Read(buf)
	require.NoError(t, err)

	expectedOut := strings.Join([]string{p1Content, p3Content}, "\n\n") + "\n"
	require.Equal(t, expectedOut, string(buf[:n]))

	policyFile, err := ioutil.TempFile(os.TempDir(), "testaudiencesdumppolicycmd-")
	require.NoError(t, err)
	defer func() {
		policyFile.Close()
		os.Remove(policyFile.Name())
	}()
	cmd.Filepath = policyFile.Name()
	require.NoError(t, cmd.Run(cfg))

	got, err := ioutil.ReadFile(policyFile.Name())
	require.NoError(t, err)
	require.Equal(t, expectedOut, string(got))
}
