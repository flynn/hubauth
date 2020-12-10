package cli

import (
	"context"
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	"github.com/flynn/hubauth/pkg/hubauth"
	"github.com/flynn/hubauth/pkg/policy"
	"github.com/jedib0t/go-pretty/v6/table"
)

type policiesCmd struct {
	New      policiesNewCmd      `kong:"cmd,help='dump a new empty policy document on stdout'"`
	List     policiesListCmd     `kong:"cmd,help='list policies',default:'1'"`
	Dump     policiesDumpCmd     `kong:"cmd,help='dump a policy content on stdout'"`
	Validate policiesValidateCmd `kong:"cmd,help='validate a policy file'"`
	Import   policiesImportCmd   `kong:"cmd,help='import a policy'"`
	Update   policiesUpdateCmd   `kong:"cmd,help='update a policy'"`
	Delete   policiesDeleteCmd   `kong:"cmd,help='delete a policy'"`
}

type policiesNewCmd struct {
	Filepath string `kong:"name='filepath',short='f',help='optionnal filepath where the policy is written (default: stdout)'"`
}

func (c *policiesNewCmd) Run(cfg *Config) error {
	template := `// This is a template policy
		policy "dummy" {
			rules {
				// This is a dummy rule
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

	d, err := policy.Parse(strings.NewReader(template))
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

	fmt.Println(out)
	return nil
}

type policiesListCmd struct{}

func (c *policiesListCmd) Run(cfg *Config) error {
	policies, err := cfg.DB.ListBiscuitPolicies(context.Background())
	if err != nil {
		return err
	}
	t := table.NewWriter()
	t.SetOutputMirror(os.Stdout)
	t.AppendHeader(table.Row{"ID", "Description", "Groups", "CreateTime", "UpdateTime"})
	for _, p := range policies {
		t.AppendRow(table.Row{p.ID, getPolicyFirstComment(p), p.Groups, p.CreateTime, p.UpdateTime})
	}
	t.Render()
	return nil
}

type policiesDumpCmd struct {
	PolicyIDs []string `kong:"name='policy-ids',help='comma separated policy IDs to dump (default: all)'"`
}

func (c *policiesDumpCmd) Run(cfg *Config) error {
	allPolicies := ""
	if len(c.PolicyIDs) > 0 {
		for _, id := range c.PolicyIDs {
			p, err := cfg.DB.GetBiscuitPolicy(context.Background(), id)
			if err != nil {
				return err
			}

			allPolicies += p.Content
		}
	} else {
		policies, err := cfg.DB.ListBiscuitPolicies(context.Background())
		if err != nil {
			return err
		}
		for _, p := range policies {
			allPolicies += p.Content
		}
	}

	doc, err := policy.Parse(strings.NewReader(allPolicies))
	if err != nil {
		return err
	}

	out, err := policy.Print(doc)
	if err != nil {
		return err
	}
	fmt.Printf("%s\n", out)
	return nil
}

type policiesImportCmd struct {
	Filepath string `kong:"required,name='filepath',short='f',help='a file containing policy definitions'"`
}

func (c *policiesImportCmd) Run(cfg *Config) error {
	content, err := ioutil.ReadFile(c.Filepath)
	if err != nil {
		return err
	}

	doc, err := policy.Parse(strings.NewReader(string(content)))
	if err != nil {
		return err
	}

	for _, p := range doc.Policies {
		content := policy.PrintPolicy(p)
		id, err := cfg.DB.CreateBiscuitPolicy(context.Background(), &hubauth.BiscuitPolicy{
			Content: string(content),
		})
		if err != nil {
			return err
		}

		fmt.Printf("Imported policy %q: %s\n", *p.Name, id)
	}
	return nil
}

type policiesValidateCmd struct {
	Filepath string `kong:"required,name='filepath',short='f',help='a file containing policy definitions'"`
}

func (c *policiesValidateCmd) Run(cfg *Config) error {
	content, err := ioutil.ReadFile(c.Filepath)
	if err != nil {
		return err
	}

	_, err = policy.ParseNamed(c.Filepath, strings.NewReader(string(content)))
	if err != nil {
		return err
	}

	return nil
}

type policiesUpdateCmd struct {
	PolicyID     string   `kong:"required,name='policy-id',help='a policy ID to update'"`
	AddGroups    []string `kong:"name='add-groups',help='comma separated list of groups to add on the policy'"`
	DeleteGroups []string `kong:"name='delete-groups',help='comma separated list of groups to delete from the policy'"`
}

func (c *policiesUpdateCmd) Run(cfg *Config) error {
	var mut []*hubauth.BiscuitPolicyMutation
	for _, g := range c.AddGroups {
		mut = append(mut, &hubauth.BiscuitPolicyMutation{
			Op:    hubauth.BiscuitPolicyMutationOpAddGroup,
			Group: g,
		})
	}
	for _, g := range c.DeleteGroups {
		mut = append(mut, &hubauth.BiscuitPolicyMutation{
			Op:    hubauth.BiscuitPolicyMutationOpDeleteGroup,
			Group: g,
		})
	}
	if err := cfg.DB.MutateBiscuitPolicy(context.Background(), c.PolicyID, mut); err != nil {
		return err
	}
	return nil
}

type policiesDeleteCmd struct {
	PolicyID string `kong:"required,name='policy-id',help='a policy ID to delete'"`
}

func (c *policiesDeleteCmd) Run(cfg *Config) error {
	return cfg.DB.DeleteBiscuitPolicy(context.Background(), c.PolicyID)
}

// getPolicyFirstComment parse the policy content and returns the first policy
// comment line if it exists. On error or when not set, an empty string is returned.
func getPolicyFirstComment(p *hubauth.BiscuitPolicy) string {
	doc, err := policy.Parse(strings.NewReader(p.Content))
	if err != nil {
		return ""
	}
	if len(doc.Policies) == 0 {
		return ""
	}
	if len(doc.Policies[0].Comments) == 0 {
		return ""
	}
	return string(*doc.Policies[0].Comments[0])
}
