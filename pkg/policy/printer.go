package policy

import (
	"fmt"
	"strings"

	"github.com/flynn/biscuit-go/parser"
)

func Print(d *Document) (string, error) {
	p := &printer{
		indent: 0,
		out:    &strings.Builder{},
	}

	for i, policy := range d.Policies {
		p.printPolicy(policy)
		if i != len(d.Policies)-1 {
			p.write("\n")
		}
	}

	return p.out.String(), nil
}

func PrintPolicy(policy *DocumentPolicy) string {
	p := &printer{
		indent: 0,
		out:    &strings.Builder{},
	}

	p.printPolicy(policy)

	return p.out.String()
}

type printer struct {
	indent int
	out    *strings.Builder
}

func (p *printer) write(format string, args ...interface{}) {
	format = strings.ReplaceAll(format, "\n", "\n"+strings.Repeat("    ", p.indent))
	p.out.WriteString(fmt.Sprintf(format, args...))
}

func (p *printer) printPolicy(policy *DocumentPolicy) {
	for _, c := range policy.Comments {
		p.write("// %s\n", *c)
	}

	p.write("policy %q {", *policy.Name)

	if len(policy.Rules) > 0 {
		p.indent++
		p.write("\nrules {")
		p.indent++
		for _, r := range policy.Rules {
			p.write("\n")
			p.printRule(r)
		}
		p.indent--
		p.write("\n")
		p.indent--
		p.write("}\n")
	}

	if len(policy.Caveats) > 0 {
		p.indent++
		p.write("\ncaveats {")
		for i, c := range policy.Caveats {
			p.indent++
			p.printCaveat(c)
			if i != len(policy.Caveats)-1 {
				p.write(", ")
			}
		}
		p.indent--
		p.write("}\n")
	}

	p.write("}\n")
}

func (p *printer) printRule(rule *parser.Rule) {
	for _, c := range rule.Comments {
		p.write("// %s\n", *c)
	}

	p.write("*")
	p.printPredicate(rule.Head)
	p.indent++
	p.write("\n")

	for i, b := range rule.Body {
		if i == 0 {
			p.write("<-  ")
		} else {
			p.write("    ")
		}
		p.printPredicate(b)
		if i != len(rule.Body)-1 {
			p.write(",\n")
		}
	}

	if len(rule.Constraints) > 0 {
		p.write("\n")
	}

	for i, c := range rule.Constraints {
		if i == 0 {
			p.write("@   ")
		} else {
			p.write("    ")
		}
		p.printConstraint(c)
		if i != len(rule.Constraints)-1 {
			p.write(",\n")
		}
	}
	p.indent--
}

func (p *printer) printCaveat(c *parser.Caveat) {
	p.write("[\n")
	for j, r := range c.Queries {
		if j != 0 {
			p.write("||")
			p.indent++
			p.write("\n")
		}
		p.printRule(r)
		if j != len(c.Queries)-1 {
			p.indent--
			p.write("\n")
		}
	}
	p.indent--
	p.write("\n]")
}

func (p *printer) printPredicate(pred *parser.Predicate) {
	p.write("%s(%s)", *pred.Name, strings.Join(atomsToString(pred.IDs), ", "))
}

func (p *printer) printConstraint(c *parser.Constraint) {
	switch {
	case c.FunctionConstraint != nil:
		p.printFunctionConstraint(c.FunctionConstraint)
	case c.VariableConstraint != nil:
		p.printVariableConstraint(c.VariableConstraint)
	}
}

func (p *printer) printFunctionConstraint(c *parser.FunctionConstraint) {
	p.write("%s($%s, %q)", *c.Function, *c.Variable, *c.Argument)
}

func (p *printer) printVariableConstraint(c *parser.VariableConstraint) {
	var op, target string
	switch {
	case c.Bytes != nil:
		op = *c.Bytes.Operation
		target = c.Bytes.Target.String()
	case c.Date != nil:
		op = *c.Date.Operation
		target = fmt.Sprintf("%q", *c.Date.Target)
	case c.Int != nil:
		op = *c.Int.Operation
		target = fmt.Sprintf("%d", *c.Int.Target)
	case c.Set != nil:
		op = "in"
		if c.Set.Not {
			op = "not in"
		}

		switch {
		case c.Set.Bytes != nil:
			members := make([]string, 0, len(c.Set.Bytes))
			for _, b := range c.Set.Bytes {
				members = append(members, b.String())
			}
			target = fmt.Sprintf("[%s]", strings.Join(members, ", "))
		case c.Set.Int != nil:
			members := make([]string, 0, len(c.Set.Int))
			for _, i := range c.Set.Int {
				members = append(members, fmt.Sprintf("%d", i))
			}
			target = fmt.Sprintf("[%s]", strings.Join(members, ", "))
		case c.Set.String != nil:
			members := make([]string, 0, len(c.Set.String))
			for _, s := range c.Set.String {
				members = append(members, fmt.Sprintf("%q", s))
			}
			target = fmt.Sprintf("[%s]", strings.Join(members, ", "))
		case c.Set.Symbols != nil:
			members := make([]string, 0, len(c.Set.Symbols))
			for _, s := range c.Set.Symbols {
				members = append(members, fmt.Sprintf("#%s", s))
			}
			target = fmt.Sprintf("[%s]", strings.Join(members, ", "))
		}
	case c.String != nil:
		op = *c.String.Operation
		target = fmt.Sprintf("%q", *c.String.Target)
	}
	p.write("$%s %s %s", *c.Variable, op, target)
}

func atomsToString(atoms []*parser.Atom) []string {
	out := make([]string, 0, len(atoms))
	for _, a := range atoms {
		var atomStr string
		switch {
		case a.Bytes != nil:
			atomStr = a.Bytes.String()
		case a.Integer != nil:
			atomStr = fmt.Sprintf("%d", *a.Integer)
		case a.Set != nil:
			atomStr = fmt.Sprintf("[%s]", strings.Join(atomsToString(a.Set), ", "))
		case a.String != nil:
			atomStr = fmt.Sprintf("%q", *a.String)
		case a.Symbol != nil:
			atomStr = fmt.Sprintf("#%s", *a.Symbol)
		case a.Variable != nil:
			atomStr = fmt.Sprintf("$%s", *a.Variable)
		}

		out = append(out, atomStr)
	}
	return out
}
