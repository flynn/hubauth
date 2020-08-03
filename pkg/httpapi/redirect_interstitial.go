package httpapi

import (
	"html/template"
	"io"
)

var redirectInterstitialHTMLTemplate = template.Must(template.New("page").Parse(`<!doctype html>
<html>
<head>
<title>Flynn Hub Auth</title>
</head>
<body>
<h1>Flynn Auth</h1>
<p>An application running on your computer would like access to Flynn credentials. You should only allow this request if you initiated it.</p>
<br>
<button onclick="window.location.href='{{.}}'">Allow Access</button>
</body>
</html>`))

func redirectInterstitialHTML(url string, out io.Writer) error {
	return redirectInterstitialHTMLTemplate.Execute(out, url)
}
