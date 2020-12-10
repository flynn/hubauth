package policy

import (
	"strings"
	"testing"

	"github.com/flynn/biscuit-go/parser"
	"github.com/stretchr/testify/require"
)

func TestParse(t *testing.T) {
	definition := `
		// admin policy comment
		policy "admin" {
			rules {
				// rule 1 comment
				*authorized($0) 
					<- namespace(#ambient, $0)
					@  prefix($0, "demo.v1")
			}
			caveats {[
				// caveat 1 comment
				*caveat0($0) <- authorized($0)
			]}
		}
		
		policy "developer" {
			rules {
				*authorized("demo.v1.Account", $1) 
					<- 	namespace(#ambient, "demo.v1.Account"),
						method(#ambient, $1),
						arg(#ambient, "env", $2)
					@	$1 in ["Create", "Read", "Update"],
						$2 in ["DEV", "STAGING"]
				*authorized("demo.v1.Account", "Read")
					<- 	namespace(#ambient, "demo.v1.Account"),
						method(#ambient, "Read"),
						arg(#ambient, "env", "PROD")
			}
			caveats {
				[*caveat1($1) <- authorized("demo.v1.Account", $1)]
			}
		}
		
		policy "auditor" {
			rules {
				*authorized("demo.v1.Account", "Read")
					<- 	namespace(#ambient, "demo.v1.Account"),
						method(#ambient, "Read"),
						arg(#ambient, "env", "DEV")
			}
			caveats {
				[*caveat2("Read") <- authorized("demo.v1.Account", "Read")]
			}
		}
	`

	doc, err := Parse(strings.NewReader(definition))
	require.NoError(t, err)

	expectedPolicies := &Document{
		Policies: []*DocumentPolicy{{
			Name:     sptr("admin"),
			Comments: []*parser.Comment{commentptr("admin policy comment")},
			Rules: []*parser.Rule{
				{
					Comments: []*parser.Comment{commentptr("rule 1 comment")},
					Head:     &parser.Predicate{Name: sptr("authorized"), IDs: []*parser.Atom{{Variable: varptr("0")}}},
					Body: []*parser.Predicate{
						{Name: sptr("namespace"), IDs: []*parser.Atom{{Symbol: symptr("ambient")}, {Variable: varptr("0")}}},
					},
					Constraints: []*parser.Constraint{
						{FunctionConstraint: &parser.FunctionConstraint{
							Function: sptr("prefix"),
							Variable: varptr("0"),
							Argument: sptr("demo.v1"),
						}},
					},
				},
			},
			Caveats: []*parser.Caveat{{Queries: []*parser.Rule{
				{
					Comments: []*parser.Comment{commentptr("caveat 1 comment")},
					Head:     &parser.Predicate{Name: sptr("caveat0"), IDs: []*parser.Atom{{Variable: varptr("0")}}},
					Body: []*parser.Predicate{
						{Name: sptr("authorized"), IDs: []*parser.Atom{{Variable: varptr("0")}}},
					},
				},
			}}},
		},
			{
				Name: sptr("developer"),
				Rules: []*parser.Rule{
					{
						Head: &parser.Predicate{Name: sptr("authorized"), IDs: []*parser.Atom{
							{String: sptr("demo.v1.Account")},
							{Variable: varptr("1")},
						}},
						Body: []*parser.Predicate{
							{Name: sptr("namespace"), IDs: []*parser.Atom{{Symbol: symptr("ambient")}, {String: sptr("demo.v1.Account")}}},
							{Name: sptr("method"), IDs: []*parser.Atom{{Symbol: symptr("ambient")}, {Variable: varptr("1")}}},
							{Name: sptr("arg"), IDs: []*parser.Atom{{Symbol: symptr("ambient")}, {String: sptr("env")}, {Variable: varptr("2")}}},
						},
						Constraints: []*parser.Constraint{
							{
								VariableConstraint: &parser.VariableConstraint{
									Variable: varptr("1"),
									Set: &parser.Set{
										Not:    false,
										String: []string{"Create", "Read", "Update"},
									},
								},
							},
							{
								VariableConstraint: &parser.VariableConstraint{
									Variable: varptr("2"),
									Set: &parser.Set{
										Not:    false,
										String: []string{"DEV", "STAGING"},
									},
								},
							},
						},
					},
					{
						Head: &parser.Predicate{Name: sptr("authorized"), IDs: []*parser.Atom{{String: sptr("demo.v1.Account")}, {String: sptr("Read")}}},
						Body: []*parser.Predicate{
							{Name: sptr("namespace"), IDs: []*parser.Atom{{Symbol: symptr("ambient")}, {String: sptr("demo.v1.Account")}}},
							{Name: sptr("method"), IDs: []*parser.Atom{{Symbol: symptr("ambient")}, {String: sptr("Read")}}},
							{Name: sptr("arg"), IDs: []*parser.Atom{{Symbol: symptr("ambient")}, {String: sptr("env")}, {String: sptr("PROD")}}},
						},
					},
				},
				Caveats: []*parser.Caveat{{Queries: []*parser.Rule{
					{
						Head: &parser.Predicate{Name: sptr("caveat1"), IDs: []*parser.Atom{{Variable: varptr("1")}}},
						Body: []*parser.Predicate{
							{Name: sptr("authorized"), IDs: []*parser.Atom{{String: sptr("demo.v1.Account")}, {Variable: varptr("1")}}},
						},
					},
				}}},
			},
			{
				Name: sptr("auditor"),
				Rules: []*parser.Rule{
					{
						Head: &parser.Predicate{Name: sptr("authorized"), IDs: []*parser.Atom{{String: sptr("demo.v1.Account")}, {String: sptr("Read")}}},
						Body: []*parser.Predicate{
							{Name: sptr("namespace"), IDs: []*parser.Atom{{Symbol: symptr("ambient")}, {String: sptr("demo.v1.Account")}}},
							{Name: sptr("method"), IDs: []*parser.Atom{{Symbol: symptr("ambient")}, {String: sptr("Read")}}},
							{Name: sptr("arg"), IDs: []*parser.Atom{{Symbol: symptr("ambient")}, {String: sptr("env")}, {String: sptr("DEV")}}},
						},
					},
				},
				Caveats: []*parser.Caveat{{Queries: []*parser.Rule{
					{
						Head: &parser.Predicate{Name: sptr("caveat2"), IDs: []*parser.Atom{{String: sptr("Read")}}},
						Body: []*parser.Predicate{
							{Name: sptr("authorized"), IDs: []*parser.Atom{{String: sptr("demo.v1.Account")}, {String: sptr("Read")}}},
						},
					},
				}}},
			},
		},
	}

	require.Equal(t, len(expectedPolicies.Policies), len(doc.Policies))
	for i, expectedPolicy := range expectedPolicies.Policies {
		require.Equal(t, doc.Policies[i], expectedPolicy)
	}
}

func sptr(s string) *string {
	return &s
}

func symptr(s string) *parser.Symbol {
	sym := parser.Symbol(s)
	return &sym
}

func varptr(s string) *parser.Variable {
	v := parser.Variable(s)
	return &v
}

func commentptr(s string) *parser.Comment {
	c := parser.Comment(s)
	return &c
}
