package httpapi

import (
	"html/template"
	"io"
)

var codeDisplayHTMLTemplate = template.Must(template.New("page").Parse(`<!doctype html>
<html>
<head>
<title>Flynn Hub Auth Code</title>
</head>
<body>
<h1>Flynn Auth Code</h1>
<p>Copy this code and paste it into the application that requested it to continue.</p>
<textarea cols="50" rows="4" readonly onclick="this.select()" style="font-family: monospace">{{.}}</textarea>
<br>
<button onclick="navigator.clipboard.writeText('{{.}}')">Copy</button>
</body>
</html>`))

func codeDisplayHTML(code string, out io.Writer) error {
	return codeDisplayHTMLTemplate.Execute(out, code)
}
