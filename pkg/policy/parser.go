package policy

import (
	"fmt"
	"io"

	"github.com/alecthomas/participle/v2"
	"github.com/alecthomas/participle/v2/lexer/stateful"
	"github.com/flynn/biscuit-go"
	"github.com/flynn/biscuit-go/parser"
)

var defaultParserOptions = append(parser.DefaultParserOptions, participle.Lexer(policyLexer))

var policyLexer = stateful.MustSimple(append(
	parser.BiscuitLexerRules,
	stateful.Rule{Name: "Policy", Pattern: `policy`},
))

type Document struct {
	Policies []*DocumentPolicy `@@*`
}

type DocumentPolicy struct {
	Comments []*parser.Comment `@Comment*`
	Name     *string           `"policy"  @String "{"`
	Rules    []*parser.Rule    `("rules" "{" @@* "}")?`
	Caveats  []*parser.Caveat  `("caveats" "{" (@@ ("," @@+)*)* "}")? "}"`
}

func (d *DocumentPolicy) BiscuitRules() ([]biscuit.Rule, error) {
	rules := make([]biscuit.Rule, 0, len(d.Rules))
	for _, r := range d.Rules {
		rule, err := r.ToBiscuit()
		if err != nil {
			return nil, err
		}
		rules = append(rules, *rule)
	}
	return rules, nil
}

func (d *DocumentPolicy) BiscuitCaveats() ([]biscuit.Caveat, error) {
	caveats := make([]biscuit.Caveat, 0, len(d.Caveats))
	for _, c := range d.Caveats {
		caveat, err := c.ToBiscuit()
		if err != nil {
			return nil, err
		}

		caveats = append(caveats, *caveat)
	}

	return caveats, nil
}

var documentParser = participle.MustBuild(&Document{}, defaultParserOptions...)

func Parse(r io.Reader) (*Document, error) {
	return ParseNamed("policy", r)
}

func ParseNamed(filename string, r io.Reader) (*Document, error) {
	parsed := &Document{}
	if err := documentParser.Parse(filename, r, parsed); err != nil {
		return nil, err
	}

	policies := make(map[string]DocumentPolicy, len(parsed.Policies))
	for _, p := range parsed.Policies {
		if _, exists := policies[*p.Name]; exists {
			return nil, fmt.Errorf("parse error: duplicate policy %q", *p.Name)
		}
	}

	return parsed, nil
}
