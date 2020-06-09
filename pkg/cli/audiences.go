package cli

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"strings"

	"github.com/flynn/hubauth/pkg/hubauth"
	"github.com/jedib0t/go-pretty/v6/table"
	"google.golang.org/genproto/googleapis/cloud/kms/v1"
)

type audiencesCmd struct {
	List      audiencesListCmd      `kong:"cmd,help='list audiences',default:'1'"`
	Create    audiencesCreateCmd    `kong:"cmd,help='create audience'"`
	SetPolicy audiencesSetPolicyCmd `kong:"cmd,name='set-policy',help='set audience auth policy'"`
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
		return fmt.Errorf("error parsing audience URL: %s", err)
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
		return fmt.Errorf("error creating audience key: %s", err)
	}

	return cfg.DB.CreateAudience(ctx, &hubauth.Audience{
		URL:       "https://" + u.Host,
		ClientIDs: c.ClientIDs,
	})
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