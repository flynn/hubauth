package cli

import (
	"context"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"net/url"
	"os"
	"strings"

	"github.com/flynn/hubauth/pkg/hubauth"
	"github.com/flynn/hubauth/pkg/policy"
	"github.com/jedib0t/go-pretty/v6/table"
	"google.golang.org/genproto/googleapis/cloud/kms/v1"
)

type audiencesCmd struct {
	List            audiencesListCmd             `kong:"cmd,help='list audiences',default:'1'"`
	Create          audiencesCreateCmd           `kong:"cmd,help='create audience'"`
	UpdateType      audienceUpdateTypeCmd        `kong:"cmd,name='update-type',help='change audience type'"`
	UpdateClientIDs audiencesUpdateClientsIDsCmd `kong:"cmd,name='update-client-ids',help='add or remove audience client IDs'"`
	Delete          audiencesDeleteCmd           `kong:"cmd,help='delete audience and all its keys'"`

	ListUserGroups   audiencesListUserGroupsCmd   `kong:"cmd,name='list-user-groups',help='list audience user groups'"`
	SetUserGroups    audiencesSetUserGroupsCmd    `kong:"cmd,name='set-user-groups',help='set audience auth user groups'"`
	UpdateUserGroups audiencesUpdateUserGroupsCmd `kong:"cmd,name='update-user-groups',help='modify audience user groups api user or groups'"`
	DeleteUserGroups audiencesDeleteUserGroupsCmd `kong:"cmd,name='delete-user-groups',help='delete audience auth user groups'"`

	Key audiencesKeyCmd `kong:"cmd,help='get audience public key'"`

	ListPolicies audiencesListPoliciesCmd `kong:"cmd,name='list-policies',help='list audience policies'"`
	DumpPolicies audiencesDumpPoliciesCmd `kong:"cmd,name='dump-policies',help='dump audience policies'"`
	SetPolicies  audiencesSetPoliciesCmd  `kong:"cmd,name='set-policies',help='set audience policies'"`
	UpdatePolicy audiencesUpdatePolicyCmd `kong:"cmd,name='update-policy',help='modify audience policy content or groups'"`
	DeletePolicy audiencesDeletePolicyCmd `kong:"cmd,name='delete-policy',help='delete audience policy'"`

	NewPolicy        audiencesNewPolicyCmd        `kong:"cmd,name='new-policy',help='print a new empty policy document on stdout'"`
	ValidatePolicies audiencesValidatePoliciesCmd `kong:"cmd,name='validate-policies',help='validate a policy file'"`
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
		Op:   hubauth.AudienceMutationSetType,
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
	u, err := url.Parse(c.AudienceURL)
	if err != nil {
		return fmt.Errorf("error parsing audience URL: %w", err)
	}

	versions, err := cfg.KMS.ListCryptoKeyVersions(context.Background(), &kms.ListCryptoKeyVersionsRequest{
		Parent: fmt.Sprintf("projects/%s/locations/%s/keyRings/%s/cryptoKeys/%s",
			cfg.ProjectID,
			c.KMSLocation,
			c.KMSKeyring,
			strings.Replace(u.Host, ".", "_", -1),
		),
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

type audiencesListUserGroupsCmd struct {
	AudienceURL string `kong:"required,name='audience-url',help='audience URL'"`
}

func (c *audiencesListUserGroupsCmd) Run(cfg *Config) error {
	audience, err := cfg.DB.GetAudience(context.Background(), c.AudienceURL)
	if err != nil {
		return err
	}

	t := table.NewWriter()
	t.SetOutputMirror(os.Stdout)
	t.AppendHeader(table.Row{"Domain", "APIUser", "Groups"})
	for _, ug := range audience.UserGroups {
		t.AppendRow(table.Row{ug.Domain, ug.APIUser, ug.Groups})
	}
	t.Render()
	return nil
}

type audiencesSetUserGroupsCmd struct {
	AudienceURL string   `kong:"required,name='audience-url',help='audience URL'"`
	Domain      string   `kong:"required,help='G Suite domain name'"`
	APIUser     string   `kong:"required,name='api-user',help='G Suite user email to impersonate for API calls'"`
	Groups      []string `kong:"required,help='comma-separated group IDs'"`
}

func (c *audiencesSetUserGroupsCmd) Run(cfg *Config) error {
	mut := &hubauth.AudienceMutation{
		Op: hubauth.AudienceMutationOpSetUserGroups,
		UserGroups: hubauth.GoogleUserGroups{
			Domain:  c.Domain,
			APIUser: c.APIUser,
			Groups:  c.Groups,
		},
	}
	return cfg.DB.MutateAudience(context.Background(), c.AudienceURL, []*hubauth.AudienceMutation{mut})
}
		})


func (c *audiencesDeleteUserGroupsCmd) Run(cfg *Config) error {
	mut := &hubauth.AudienceMutation{
		Op: hubauth.AudienceMutationOpDeleteUserGroups,
		UserGroups: hubauth.GoogleUserGroups{
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
	t.AppendHeader(table.Row{"Name", "Groups", "Description"})
	for _, p := range audience.Policies {
		t.AppendRow(table.Row{p.Name, p.Groups, getFirstComment(p)})
	}
	t.Render()
	return nil
}

// getFirstComment parse the policy content and returns the first policy
// comment line if it exists. On failure to parse the policy content, or when unset, an empty string is returned.
func getFirstComment(p *hubauth.BiscuitPolicy) string {
	doc, err := policy.ParseDocumentPolicy(strings.NewReader(p.Content))
	if err != nil {
		return ""
	}
	if len(doc.Comments) == 0 {
		return ""
	}
	return string(*doc.Comments[0])
}

type audiencesSetPoliciesCmd struct {
	AudienceURL string   `kong:"required,name='audience-url',help='audience URL'"`
	Filepath    string   `kong:"required,name='filepath',help='policy file'"`
	Groups      []string `kong:"help='comma-separated group IDs'"`
}

// Run parses Filepath for a list of policies, and creates or updates them on the audience identified by AudienceURL,
// forcing their groups to the provided Groups.
func (c *audiencesSetPoliciesCmd) Run(cfg *Config) error {
	f, err := os.Open(c.Filepath)
	if err != nil {
		return err
	}

	doc, err := policy.ParseNamed(f.Name(), f)
	if err != nil {
		return err
	}

	muts := make([]*hubauth.AudienceMutation, len(doc.Policies))
	for i, p := range doc.Policies {
		muts[i] = &hubauth.AudienceMutation{
			Op: hubauth.AudienceMutationSetPolicy,
			Policy: hubauth.BiscuitPolicy{
				Name:    *p.Name,
				Content: policy.PrintPolicy(p),
				Groups:  c.Groups,
			},
		}
	}

	return cfg.DB.MutateAudience(context.Background(), c.AudienceURL, muts)
}

type audiencesUpdatePolicyCmd struct {
	AudienceURL  string   `kong:"required,name='audience-url',help='audience URL'"`
	PolicyName   string   `kong:"required,help='policy name'"`
	Filepath     string   `kong:"name='filepath',help='replace policy content from a file'"`
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
	if c.Filepath != "" {
		doc, err := parsePolicy(c.Filepath)
		if err != nil {
			return err
		}

		var mutatedPolicy *policy.DocumentPolicy
		for _, p := range doc.Policies {
			if *p.Name == c.PolicyName {
				mutatedPolicy = p
				break
			}
		}
		if mutatedPolicy == nil {
			return fmt.Errorf("policy %q not found in file %q", c.PolicyName, c.Filepath)
		}

		muts = append(muts, &hubauth.AudiencePolicyMutation{
			Op:      hubauth.AudiencePolicyMutationOpSetContent,
			Content: policy.PrintPolicy(mutatedPolicy),
		})
	}

	return cfg.DB.MutateAudiencePolicy(context.Background(), c.AudienceURL, c.PolicyName, muts)
}

type audiencesDeletePolicyCmd struct {
	AudienceURL string `kong:"required,name='audience-url',help='audience URL'"`
	PolicyName  string `kong:"required,help='policy name'"`
}

func (c *audiencesDeletePolicyCmd) Run(cfg *Config) error {
	mut := &hubauth.AudienceMutation{
		Op: hubauth.AudienceMutationDeletePolicy,
		Policy: hubauth.BiscuitPolicy{
			Name: c.PolicyName,
		},
	}
	return cfg.DB.MutateAudience(context.Background(), c.AudienceURL, []*hubauth.AudienceMutation{mut})
}

type audiencesNewPolicyCmd struct {
	Filepath string `kong:"name='filepath',short='f',help='optionnal filepath where to write the policy (default: stdout)'"`
}

var policyTemplate string = `// this is a template policy
policy "dummy" {
	rules {
		// this is a dummy rule
		*head($var1)
			<-  body1(#ambient, $name),
				body2($value)
			@   $name == "example"
	}

	caveats {[
		// this is a dummy caveat
		*head($var1)
			<-  body1(#ambient, $name),
				body2($value)
			@   $name == "example"
	]}
}`

func (c *audiencesNewPolicyCmd) Run(cfg *Config) error {
	d, err := policy.Parse(strings.NewReader(policyTemplate))
	if err != nil {
		return err
	}

	out, err := policy.Print(d)
	if err != nil {
		return err
	}

	if c.Filepath != "" {
		ioutil.WriteFile(c.Filepath, []byte(out), 0644)
		fmt.Printf("written %s\n", c.Filepath)
		return nil
	}

	fmt.Print(out)
	return nil
}

type audiencesValidatePoliciesCmd struct {
	Filepath string `kong:"required,name='filepath',short='f',help='a file containing policy definitions'"`
}

func (c *audiencesValidatePoliciesCmd) Run(cfg *Config) error {
	f, err := os.Open(c.Filepath)
	if err != nil {
		return err
	}

	_, err = policy.ParseNamed(f.Name(), f)
	if err != nil {
		return err
	}

	return nil
}

type audiencesDumpPoliciesCmd struct {
	AudienceURL string   `kong:"required,name='audience-url',help='audience URL'"`
	PolicyNames []string `kong:"name='policy-names',help='comma separated policy names to dump (default: all)'"`
	Filepath    string   `kong:"name='filepath',short='f',help='optionnal filepath where to write the policies (default: stdout)'"`
}

func (c *audiencesDumpPoliciesCmd) Run(cfg *Config) error {
	aud, err := cfg.DB.GetAudience(context.Background(), c.AudienceURL)
	if err != nil {
		return err
	}

	if len(aud.Policies) == 0 {
		return fmt.Errorf("audience %s have no policy", c.AudienceURL)
	}

	dumpPolicies := aud.Policies
	if len(c.PolicyNames) > 0 {
		dumpPolicies = make([]*hubauth.BiscuitPolicy, 0, len(c.PolicyNames))
		for _, p := range aud.Policies {
			for _, name := range c.PolicyNames {
				if name == p.Name {
					dumpPolicies = append(dumpPolicies, p)
					break
				}
			}
		}
	}

	aggContent := ""
	for _, p := range dumpPolicies {
		aggContent += p.Content
	}

	doc, err := policy.Parse(strings.NewReader(aggContent))
	if err != nil {
		return err
	}

	out, err := policy.Print(doc)
	if err != nil {
		return err
	}

	if c.Filepath != "" {
		ioutil.WriteFile(c.Filepath, []byte(out), 0644)
		fmt.Printf("written %d policies to %s\n", len(dumpPolicies), c.Filepath)
		return nil
	}

	fmt.Printf("%s", out)
	return nil
}

func parsePolicy(path string) (*policy.Document, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	doc, err := policy.ParseNamed(f.Name(), f)
	if err != nil {
		return nil, err
	}

	return doc, nil
}
