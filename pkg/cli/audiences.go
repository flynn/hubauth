package cli

import (
	"context"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"net/url"
	"os"
	"strings"

	"github.com/flynn/hubauth/pkg/hubauth"
	"github.com/jedib0t/go-pretty/v6/table"
	"google.golang.org/genproto/googleapis/cloud/kms/v1"
	kmspb "google.golang.org/genproto/googleapis/cloud/kms/v1"
	fieldmask "google.golang.org/genproto/protobuf/field_mask"
)

type audiencesCmd struct {
	List              audiencesListCmd             `kong:"cmd,help='list audiences',default:'1'"`
	Create            audiencesCreateCmd           `kong:"cmd,help='create audience'"`
	UpdateType        audienceUpdateTypeCmd        `kong:"cmd,name='update-type',help='change audience type'"`
	UpdateClientIDs   audiencesUpdateClientsIDsCmd `kong:"cmd,name='update-client-ids',help='add or remove audience client IDs'"`
	Delete            audiencesDeleteCmd           `kong:"cmd,help='delete audience and all its keys'"`
	ListPolicies      audiencesListPoliciesCmd     `kong:"cmd,name='list-policies',help='list audience policies'"`
	SetPolicy         audiencesSetPolicyCmd        `kong:"cmd,name='set-policy',help='set audience auth policy'"`
	UpdatePolicy      audiencesUpdatePolicyCmd     `kong:"cmd,name='update-policy',help='modify audience policy api user or groups'"`
	DeletePolicy      audiencesDeletePolicyCmd     `kong:"cmd,name='delete-policy',help='delete audience auth policy'"`
	Key               audiencesKeyCmd              `kong:"cmd,help='get audience public key'"`
	ListKeyVersions   audiencesListKeyVersionsCmd  `kong:"cmd,help='list audience key versions'"`
	CreateKeyVersion  audienceCreateKeyVersion     `kong:"cmd,help='create a new audience key version'"`
	DeleteKeyVersion  audiencesDeleteKeyVersion    `kong:"cmd,help='schedule an audience key version for deletion'"`
	RestoreKeyVersion audiencesRestoreKeyVersion   `kong:"cmd,help='restore an audience key version scheduled for deletion'"`
}

type audiencesListCmd struct{}

func (c *audiencesListCmd) Run(cfg *Config) error {
	audiences, err := cfg.DB.ListAudiences(context.Background())
	if err != nil {
		return err
	}
	t := table.NewWriter()
	t.SetOutputMirror(os.Stdout)
	t.AppendHeader(table.Row{"URL", "Type", "ClientIDs", "CreateTime", "UpdateTime"})
	for _, audience := range audiences {
		t.AppendRow(table.Row{audience.URL, audience.Type, audience.ClientIDs, audience.CreateTime, audience.UpdateTime})
	}
	t.Render()
	return nil
}

type audiencesCreateCmd struct {
	URL         string   `kong:"required,name='audience-url',help='audience URL'"`
	Type        string   `kong:"name='audience-type',default='flynn_controller',help='audience Type'"`
	ClientIDs   []string `kong:"name='client-ids',help='comma-separated client IDs'"`
	KMSLocation string   `kong:"name='kms-location',default='us',help='KMS keyring location'"`
	KMSKeyring  string   `kong:"name='kms-keyring',default='hubauth-audiences-us',help='KMS keyring name'"`
}

func (c *audiencesCreateCmd) Run(cfg *Config) error {
	ctx := context.Background()

	for _, id := range c.ClientIDs {
		_, err := cfg.DB.GetClient(ctx, id)
		if err != nil {
			return err
		}
	}

	u, err := url.Parse(c.URL)
	if err != nil {
		return fmt.Errorf("error parsing audience URL: %w", err)
	}
	if u.Scheme != "https" {
		return fmt.Errorf("audience URL must be https://")
	}
	if u.Path != "" {
		return fmt.Errorf("unexpected path in audience URL")
	}

	_, err = cfg.KMS.CreateCryptoKey(ctx, &kms.CreateCryptoKeyRequest{
		Parent:      fmt.Sprintf("projects/%s/locations/%s/keyRings/%s", cfg.ProjectID, c.KMSLocation, c.KMSKeyring),
		CryptoKeyId: strings.Replace(u.Host, ".", "_", -1),
		CryptoKey: &kms.CryptoKey{
			Purpose: kms.CryptoKey_ASYMMETRIC_SIGN,
			VersionTemplate: &kms.CryptoKeyVersionTemplate{
				ProtectionLevel: kms.ProtectionLevel_SOFTWARE,
				Algorithm:       kms.CryptoKeyVersion_EC_SIGN_P256_SHA256,
			},
		},
	})
	if err != nil {
		return fmt.Errorf("error creating audience key: %w", err)
	}

	return cfg.DB.CreateAudience(ctx, &hubauth.Audience{
		URL:       "https://" + u.Host,
		Type:      c.Type,
		ClientIDs: c.ClientIDs,
	})
}

type audienceUpdateTypeCmd struct {
	AudienceURL  string `kong:"required,name='audience-url',help='audience URL'"`
	AudienceType string `kong:"required,name='audience-type',help='audience type'"`
}

func (c *audienceUpdateTypeCmd) Run(cfg *Config) error {
	return cfg.DB.MutateAudience(context.Background(), c.AudienceURL, []*hubauth.AudienceMutation{{
		Op:   hubauth.AudienceMutationOpSetType,
		Type: c.AudienceType,
	}})

}

type audiencesUpdateClientsIDsCmd struct {
	AudienceURL   string   `kong:"required,name='audience-url',help='audience URL'"`
	AddClients    []string `kong:"name='add-clients',short='a',help='comma-separated client IDs to add'"`
	DeleteClients []string `kong:"name='delete-clients',short='d',help='comma-separated client IDs to delete'"`
}

func (c *audiencesUpdateClientsIDsCmd) Run(cfg *Config) error {
	var muts []*hubauth.AudienceMutation
	for _, clientID := range c.AddClients {
		muts = append(muts, &hubauth.AudienceMutation{
			Op:       hubauth.AudienceMutationOpAddClientID,
			ClientID: clientID,
		})
	}
	for _, clientID := range c.DeleteClients {
		muts = append(muts, &hubauth.AudienceMutation{
			Op:       hubauth.AudienceMutationOpDeleteClientID,
			ClientID: clientID,
		})
	}

	return cfg.DB.MutateAudience(context.Background(), c.AudienceURL, muts)
}

type audiencesDeleteCmd struct {
	AudienceURL string `kong:"required,name='audience-url',help='audience URL'"`
	KMSLocation string `kong:"name='kms-location',default='us',help='KMS keyring location'"`
	KMSKeyring  string `kong:"name='kms-keyring',default='hubauth-audiences-us',help='KMS keyring name'"`
}

func (c *audiencesDeleteCmd) Run(cfg *Config) error {
	keyName, err := cryptoKeyName(cfg.ProjectID, c.KMSLocation, c.KMSKeyring, c.AudienceURL)
	if err != nil {
		return fmt.Errorf("invalid key name: %w", err)
	}

	versions, err := cfg.KMS.ListCryptoKeyVersions(context.Background(), &kms.ListCryptoKeyVersionsRequest{
		Parent: keyName,
	})

	if err != nil {
		return fmt.Errorf("failed to retrieve crypto key versions: %w", err)
	}

	for _, version := range versions {
		if _, err = cfg.KMS.DestroyCryptoKeyVersion(context.Background(), &kms.DestroyCryptoKeyVersionRequest{
			Name: version.Name,
		}); err != nil {
			return fmt.Errorf("failed to delete crypto key version %s: %v", version.Name, err)
		}
	}

	return cfg.DB.DeleteAudience(context.Background(), c.AudienceURL)
}

type audiencesListPoliciesCmd struct {
	AudienceURL string `kong:"required,name='audience-url',help='audience URL'"`
}

func (c *audiencesListPoliciesCmd) Run(cfg *Config) error {
	audience, err := cfg.DB.GetAudience(context.Background(), c.AudienceURL)
	if err != nil {
		return err
	}

	t := table.NewWriter()
	t.SetOutputMirror(os.Stdout)
	t.AppendHeader(table.Row{"Domain", "APIUser", "Groups"})
	for _, p := range audience.Policies {
		t.AppendRow(table.Row{p.Domain, p.APIUser, p.Groups})
	}
	t.Render()
	return nil
}

type audiencesSetPolicyCmd struct {
	AudienceURL string   `kong:"required,name='audience-url',help='audience URL'"`
	Domain      string   `kong:"required,help='G Suite domain name'"`
	APIUser     string   `kong:"required,name='api-user',help='G Suite user email to impersonate for API calls'"`
	Groups      []string `kong:"required,help='comma-separated group IDs'"`
}

func (c *audiencesSetPolicyCmd) Run(cfg *Config) error {
	mut := &hubauth.AudienceMutation{
		Op: hubauth.AudienceMutationOpSetPolicy,
		Policy: hubauth.GoogleUserPolicy{
			Domain:  c.Domain,
			APIUser: c.APIUser,
			Groups:  c.Groups,
		},
	}
	return cfg.DB.MutateAudience(context.Background(), c.AudienceURL, []*hubauth.AudienceMutation{mut})
}

type audiencesUpdatePolicyCmd struct {
	AudienceURL  string   `kong:"required,name='audience-url',help='audience URL'"`
	Domain       string   `kong:"required,help='G Suite domain name'"`
	APIUser      string   `kong:"name='api-user',help='G Suite user email to impersonate for API calls'"`
	AddGroups    []string `kong:"name='add-groups',help='comma-separated group IDs to add'"`
	DeleteGroups []string `kong:"name='delete-groups',help='comma-separated group IDs to delete'"`
}

func (c *audiencesUpdatePolicyCmd) Run(cfg *Config) error {
	var muts []*hubauth.AudiencePolicyMutation
	for _, groupID := range c.AddGroups {
		muts = append(muts, &hubauth.AudiencePolicyMutation{
			Op:    hubauth.AudiencePolicyMutationOpAddGroup,
			Group: groupID,
		})
	}
	for _, groupID := range c.DeleteGroups {
		muts = append(muts, &hubauth.AudiencePolicyMutation{
			Op:    hubauth.AudiencePolicyMutationOpDeleteGroup,
			Group: groupID,
		})
	}
	if c.APIUser != "" {
		muts = append(muts, &hubauth.AudiencePolicyMutation{
			Op:      hubauth.AudiencePolicyMutationOpSetAPIUser,
			APIUser: c.APIUser,
		})
	}

	return cfg.DB.MutateAudiencePolicy(context.Background(), c.AudienceURL, c.Domain, muts)
}

type audiencesDeletePolicyCmd struct {
	AudienceURL string `kong:"required,name='audience-url',help='audience URL'"`
	Domain      string `kong:"required,help='G Suite domain name'"`
}

func (c *audiencesDeletePolicyCmd) Run(cfg *Config) error {
	mut := &hubauth.AudienceMutation{
		Op: hubauth.AudienceMutationOpDeletePolicy,
		Policy: hubauth.GoogleUserPolicy{
			Domain: c.Domain,
		},
	}
	return cfg.DB.MutateAudience(context.Background(), c.AudienceURL, []*hubauth.AudienceMutation{mut})
}

type audiencesKeyCmd struct {
	URL         string `kong:"required,name='audience-url',help='audience URL'"`
	KeyVersion  int    `kong:"name='key-version',help='key version',default=1"`
	KMSLocation string `kong:"name='kms-location',default='us',help='KMS keyring location'"`
	KMSKeyring  string `kong:"name='kms-keyring',default='hubauth-audiences-us',help='KMS keyring name'"`
}

func (c *audiencesKeyCmd) Run(cfg *Config) error {
	ctx := context.Background()
	keyVersion, err := cryptoKeyVersion(cfg.ProjectID, c.KMSLocation, c.KMSKeyring, c.URL, c.KeyVersion)
	if err != nil {
		return fmt.Errorf("invalid key version: %w", err)
	}

	res, err := cfg.KMS.GetPublicKey(ctx, &kms.GetPublicKeyRequest{
		Name: keyVersion,
	})
	if err != nil {
		return fmt.Errorf("failed to fetch public key: %w", err)
	}

	b, _ := pem.Decode([]byte(res.Pem))
	fmt.Println(base64.URLEncoding.EncodeToString(b.Bytes))
	return nil
}

type audiencesListKeyVersionsCmd struct {
	URL         string `kong:"required,name='audience-url',help='audience URL'"`
	KMSLocation string `kong:"name='kms-location',default='us',help='KMS keyring location'"`
	KMSKeyring  string `kong:"name='kms-keyring',default='hubauth-audiences-us',help='KMS keyring name'"`
}

func (c *audiencesListKeyVersionsCmd) Run(cfg *Config) error {
	keyName, err := cryptoKeyName(cfg.ProjectID, c.KMSLocation, c.KMSKeyring, c.URL)
	if err != nil {
		return fmt.Errorf("invalid key name: %w", err)
	}
	versions, err := cfg.KMS.ListCryptoKeyVersions(context.Background(), &kms.ListCryptoKeyVersionsRequest{
		Parent: keyName,
	})
	if err != nil {
		return fmt.Errorf("failed to list versions: %w", err)
	}

	t := table.NewWriter()
	t.SetOutputMirror(os.Stdout)
	t.AppendHeader(table.Row{"Version", "State", "Alg", "CreateTime", "DestroyTime"})
	for _, v := range versions {
		split := strings.Split(v.Name, "/")
		versionID := split[len(split)-1]

		destroyedAt := ""
		if v.DestroyTime != nil {
			destroyedAt = v.DestroyTime.AsTime().String()
		}

		t.AppendRow(table.Row{versionID, v.State, v.Algorithm, v.CreateTime.AsTime(), destroyedAt})
	}
	t.Render()

	return nil
}

type audienceCreateKeyVersion struct {
	URL         string `kong:"required,name='audience-url',help='audience URL'"`
	KMSLocation string `kong:"name='kms-location',default='us',help='KMS keyring location'"`
	KMSKeyring  string `kong:"name='kms-keyring',default='hubauth-audiences-us',help='KMS keyring name'"`
}

func (c *audienceCreateKeyVersion) Run(cfg *Config) error {
	keyName, err := cryptoKeyName(cfg.ProjectID, c.KMSLocation, c.KMSKeyring, c.URL)
	if err != nil {
		return fmt.Errorf("invalid key name: %w", err)
	}

	v, err := cfg.KMS.CreateCryptoKeyVersion(context.Background(), &kms.CreateCryptoKeyVersionRequest{
		Parent: keyName,
	})
	if err != nil {
		return fmt.Errorf("error creating audience key: %w", err)
	}

	fmt.Println(v.Name)

	return nil
}

type audiencesDeleteKeyVersion struct {
	URL         string `kong:"required,name='audience-url',help='audience URL'"`
	KeyVersion  int    `kong:"required,name='key-version',help='key version'"`
	KMSLocation string `kong:"name='kms-location',default='us',help='KMS keyring location'"`
	KMSKeyring  string `kong:"name='kms-keyring',default='hubauth-audiences-us',help='KMS keyring name'"`
}

func (c *audiencesDeleteKeyVersion) Run(cfg *Config) error {
	keyVersion, err := cryptoKeyVersion(cfg.ProjectID, c.KMSLocation, c.KMSKeyring, c.URL, c.KeyVersion)
	if err != nil {
		return fmt.Errorf("invalid key version: %w", err)
	}

	if _, err = cfg.KMS.DestroyCryptoKeyVersion(context.Background(), &kms.DestroyCryptoKeyVersionRequest{
		Name: keyVersion,
	}); err != nil {
		return fmt.Errorf("failed to delete crypto key version: %w", err)
	}

	return nil
}

type audiencesRestoreKeyVersion struct {
	URL         string `kong:"required,name='audience-url',help='audience URL'"`
	KeyVersion  int    `kong:"required,name='key-version',help='key version'"`
	KMSLocation string `kong:"name='kms-location',default='us',help='KMS keyring location'"`
	KMSKeyring  string `kong:"name='kms-keyring',default='hubauth-audiences-us',help='KMS keyring name'"`
}

func (c *audiencesRestoreKeyVersion) Run(cfg *Config) error {
	keyVersion, err := cryptoKeyVersion(cfg.ProjectID, c.KMSLocation, c.KMSKeyring, c.URL, c.KeyVersion)
	if err != nil {
		return fmt.Errorf("invalid key version: %w", err)
	}

	key, err := cfg.KMS.RestoreCryptoKeyVersion(context.Background(), &kms.RestoreCryptoKeyVersionRequest{
		Name: keyVersion,
	})
	if err != nil {
		return err
	}

	// restored keys are in disabled state, so this enable it
	_, err = cfg.KMS.UpdateCryptoKeyVersion(context.Background(), &kms.UpdateCryptoKeyVersionRequest{
		CryptoKeyVersion: &kmspb.CryptoKeyVersion{
			Name:  key.Name,
			State: kmspb.CryptoKeyVersion_ENABLED,
		},
		UpdateMask: &fieldmask.FieldMask{
			Paths: []string{"state"},
		},
	})
	if err != nil {
		return err
	}

	return nil
}

func cryptoKeyName(projectID, kmsLocation, kmsKeyring string, audienceURL string) (string, error) {
	u, err := url.Parse(audienceURL)
	if err != nil {
		return "", err
	}
	if u.Scheme != "https" {
		return "", fmt.Errorf("audience URL must be https://")
	}
	if u.Path != "" {
		return "", fmt.Errorf("unexpected path in audience URL")
	}

	return fmt.Sprintf("projects/%s/locations/%s/keyRings/%s/cryptoKeys/%s",
		projectID,
		kmsLocation,
		kmsKeyring,
		strings.Replace(u.Host, ".", "_", -1),
	), nil
}

func cryptoKeyVersion(projectID, kmsLocation, kmsKeyring string, audienceURL string, version int) (string, error) {
	name, err := cryptoKeyName(projectID, kmsLocation, kmsKeyring, audienceURL)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%s/cryptoKeyVersions/%d", name, version), nil
}
