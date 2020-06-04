package errsource

import (
	"runtime"

	"golang.org/x/exp/errors"
)

func Source(err error) *runtime.Frame {
	errFormatter, ok := err.(errors.Formatter)
	if !ok {
		return nil
	}
	fp := &framePrinter{}
	errFormatter.FormatError(fp)
	if fp.Function == "" || fp.File == "" {
		return nil
	}
	return &fp.Frame
}

type framePrinter struct {
	runtime.Frame
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
