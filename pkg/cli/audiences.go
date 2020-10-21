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
)

type audiencesCmd struct {
	List            audiencesListCmd             `kong:"cmd,help='list audiences',default:'1'"`
	Create          audiencesCreateCmd           `kong:"cmd,help='create audience'"`
	UpdateClientIDs audiencesUpdateClientsIDsCmd `kong:"cmd,name='update-client-ids',help='add or remove audience client IDs'"`
	Delete          audiencesDeleteCmd           `kong:"cmd,help='delete audience'"`
	ListPolicies    audiencesListPoliciesCmd     `kong:"cmd,name='list-policies',help='list audience policies'"`
	SetPolicy       audiencesSetPolicyCmd        `kong:"cmd,name='set-policy',help='set audience auth policy'"`
	UpdatePolicy    audiencesUpdatePolicyCmd     `kong:"cmd,name='update-policy',help='modify audience policy api user or groups'"`
	DeletePolicy    audiencesDeletePolicyCmd     `kong:"cmd,name='delete-policy',help='delete audience auth policy'"`
	Key             audiencesKeyCmd              `kong:"cmd,help='get audience public key'"`
}

type audiencesListCmd struct{}

func (c *audiencesListCmd) Run(cfg *Config) error {
	clients, err := cfg.DB.ListAudiences(context.Background())
	if err != nil {
		return err
	}
	t := table.NewWriter()
	t.SetOutputMirror(os.Stdout)
	t.AppendHeader(table.Row{"URL", "ClientIDs", "CreateTime", "UpdateTime"})
	for _, c := range clients {
		t.AppendRow(table.Row{c.URL, c.ClientIDs, c.CreateTime, c.UpdateTime})
	}
	t.Render()
	return nil
}

type audiencesCreateCmd struct {
	URL         string   `kong:"required,name='audience-url',help='audience URL'"`
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
		ClientIDs: c.ClientIDs,
	})
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
}

func (c *audiencesDeleteCmd) Run(cfg *Config) error {
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
	KMSLocation string `kong:"name='kms-location',default='us',help='KMS keyring location'"`
	KMSKeyring  string `kong:"name='kms-keyring',default='hubauth-audiences-us',help='KMS keyring name'"`
}

func (c *audiencesKeyCmd) Run(cfg *Config) error {
	ctx := context.Background()

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

	res, err := cfg.KMS.GetPublicKey(ctx, &kms.GetPublicKeyRequest{
		Name: fmt.Sprintf("projects/%s/locations/%s/keyRings/%s/cryptoKeys/%s/cryptoKeyVersions/1", cfg.ProjectID, c.KMSLocation, c.KMSKeyring, strings.Replace(u.Host, ".", "_", -1)),
	})
	if err != nil {
		return err
	}

	b, _ := pem.Decode([]byte(res.Pem))
	fmt.Println(base64.URLEncoding.EncodeToString(b.Bytes))
	return nil
}
