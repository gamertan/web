<!-- SPDX-License-Identifier: MPL-2.0 -->

# HTML with Sandwich Hime

Gamertan Web Foundations owns reusable web-application boundaries; it does not
own HTML or a template language. [Sandwich Hime](https://sandwichhime.com/) is
the preferred companion for Gamertan applications that want HTML-first,
ahead-of-time templates with typed Go composition.

The relationship is intentionally optional:

| Application responsibility | Owner |
| --- | --- |
| Request identity, logging, security primitives, sessions, and analytics | Web Foundations packages selected by the application |
| Routing, authorization decisions, status, headers, caching, and deployment | The application |
| Visible HTML and typed component composition | Authored `.sando` templates |
| Template parsing, contextual analysis, and Go generation | Hime-san during development or CI |
| Rendering generated components | The small `sando` runtime in production |

Web Foundations does not import Sandwich Hime. Sandwich Hime does not import
Web Foundations. An application chooses both and provides the seam between
them.

## Request flow

```text
request
  -> requestmeta / selected middleware
  -> application router and handler
  -> typed view data
  -> generated Sandwich Hime component
  -> buffered sando.Render
  -> application-owned HTTP response
```

Buffer the component before committing a successful response so a rendering
error can still become a clean application error:

```go
func renderHTML(response http.ResponseWriter, request *http.Request, status int, component sando.Component) {
	var output bytes.Buffer
	if err := sando.Render(request.Context(), &output, component); err != nil {
		log.Printf("render page: %v", err)
		response.Header().Set("Cache-Control", "no-store")
		http.Error(response, "could not render page", http.StatusInternalServerError)
		return
	}
	response.Header().Set("Content-Type", "text/html; charset=utf-8")
	response.WriteHeader(status)
	_, _ = response.Write(output.Bytes())
}
```

The handler—not the template—should interpret request metadata, principals,
permissions, analytics, or storage errors. It passes only the resulting typed
display data into the component. Templates should not acquire an implicit
request global or turn middleware context into an inheritance framework.

Handwritten `sando.Component` implementations and `Trust*` values are explicit
trusted-output capabilities. Keep them conspicuous and review them separately
from ordinary untrusted values.

## Continue with the official lessons

- [Build a component, page, and small site](https://sandwichhime.com/docs/tutorial/).
- [Follow a request through a larger Go application](https://sandwichhime.com/docs/tutorial/application/).
- [Review the Sandwich Hime security boundary](https://sandwichhime.com/docs/security/).

Those tutorials own the template syntax and compiler workflow. This repository
documents only the application seam so the two projects do not drift into a
single mandatory framework.
