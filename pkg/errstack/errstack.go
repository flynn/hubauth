package errstack

import (
	"fmt"

	"golang.org/x/exp/errors"
)

func Format(err error) []byte {
	errFormatter, ok := err.(errors.Formatter)
	if !ok {
		return nil
	}
	fp := &framePrinter{}
	errFormatter.FormatError(fp)
	if fp.Function == "" || fp.File == "" {
		return nil
	}
	return []byte(fmt.Sprintf("goroutine 1 [running]:\n%s()\n\t%s:%d +0", fp.Function, fp.File, fp.Line))
}

type framePrinter struct {
	Function string
	File     string
	Line     int
}

func (p *framePrinter) Print(args ...interface{}) {}

func (p *framePrinter) Printf(format string, args ...interface{}) {
	if format == "%s\n    " && len(args) == 1 {
		if f, ok := args[0].(string); ok {
			p.Function = f
		}
	}
	if format == "%s:%d\n" && len(args) == 2 {
		if file, ok := args[0].(string); ok {
			p.File = file
		}
		if line, ok := args[1].(int); ok {
			p.Line = line
		}
	}
}

func (*framePrinter) Detail() bool {
	return true
}
