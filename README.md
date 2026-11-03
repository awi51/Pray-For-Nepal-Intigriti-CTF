# Pray-For-Nepal-Intigriti-CTF

# Pray For Nepal — Intigriti October Bonus Challenge (Professional Write-up)

> 

---

## 1. Title & Challenge Information

| Field | Value |
|---|---|
| Challenge Name | **Pray For Nepal** (Intigriti October Bonus Challenge) |
| Platform | Intigriti CTF |
| Challenge Category | Web — Client-Side / XSS (DOM-based, DOM Clobbering) |
| Difficulty | Medium (per Intigriti challenge rules, all submissions graded Medium) |
| Points | Prize-pool format (no points system): First blood €100, 3× random €50, 3× best write-up €50 |
| Challenge URL | https://challenge-brp.challenges.intigriti.io/challenge.php |
| Challenge Window | 2026-10-28 12:00 UTC → 2026-11-02 23:59 UTC |
| Author (challenge) | 1337mickey ([@sushil_phuyal](https://x.com/sushil_phuyal)) |
| Completion Date | 2026-10-30 |

**Report requirements (from the official rules):** flag in format `INTIGRITI{.*}`, payload(s) used, steps to solve, severity set to **Medium**.

---

## 2. TL;DR — Attack Summary

- **Identified vulnerability:** DOM-based XSS. The `person` query parameter is escaped server-side, but the page's JavaScript re-reads it **raw** from the URL and evaluates it as HTML through `innerHTML`.
- **Main exploitation technique:** **DOM Clobbering** — injecting attacker-controlled elements with `id`/`data-*` attributes that impersonate two internal gate elements (`#archive-latch`, `#record-anchor`) which the page's boot script resolves via `getElementById`.
- **Security mechanism bypass:** the client-side sanitiser strips `script/iframe/object/embed` tags and `on*` attributes, but **keeps `id` and `data-*` attributes** — exactly what the clobbering requires. The page's CSP (`script-src 'nonce-…' 'self'`) blocks inline code but permits the page to load its **own same-origin script**, which the attacker redirects into a gadget through the clobbered gate.
- **Final exploitation chain:** crafted link → raw `person` value → `template.innerHTML` → sanitiser (weak) → `profile.innerHTML` → boot script's gate satisfied → page self-creates `<script src="/echo.php?channel=echo&listener=alert(document.domain)//">` → echoed JS fires `alert()` → page's overridden `alert()` POSTs `/reveal.php` → flag revealed in the page's vault box.
- **Result:** `INTIGRITI{f2cb05a5-5cc1-4d1d-b7cd-084306cbd5a0}` — verified live on the challenge page in a real Chromium browser.

---

## 3. Challenge Overview

The page presents a fictional **"National Monsoon Memory Project"** — a missing-person registry themed around the Nepal monsoon ("*When the rain drowns the roads, every family deserves an answer*").

**Application functionality:**

- A person-search box — `GET /challenge.php?person=<name>`.
- Three registry entries are linked: **Sushil**, **Mickey**, **Ram**. Valid names are server-side rendered into a profile card (e.g. `Ram — mountain rescue captain and radio keeper`); unknown names render `"<name> not found"`.
- A hidden blue **vault box** (`#vault`) exists in the DOM, hidden by default — signalling a secret that can be opened.
- The landing page (`/index.php`) links solvers straight to the challenge with a "**Test your payloads**" action, and states the flag must be found and reported with severity **Medium**.

**Challenge objective:** leverage a vulnerability on the challenge page (no self-XSS, no MitM) to capture the hidden flag.

**Conditions to capture the flag:** a single visit to the crafted URL is sufficient — the page itself drives the entire chain. The only "interaction" is dismissing the proof-of-execution `alert()` dialog that the page itself displays; the flag fetch runs the moment it is closed, and the vault renders the flag.

---

## 4. Reconnaissance & Application Analysis

### 4.1 Attack surface & endpoints

Directory probing (404 vs. 403/200 differential, plus path leaks in error output — `lib/security.php` appeared in a PHP warning) identified a deliberately small application:

| Endpoint | Role |
|---|---|
| `/` , `/index.php` | Challenge landing page (rules, live window, tips link) |
| `/challenge.php` | The vulnerable page (person registry search) |
| `/echo.php` | Returns JS; refuses direct access (`403`, empty body) — behaves as a gated endpoint |
| `/reveal.php` | Serves the flag; requires the page's own call pattern — `POST` with `X-Registry-Check: 1` plus browser Fetch-Metadata headers (plain CLI-style POSTs are rejected early with a bare 403) |
| `lib/security.php` | Server-side include (reachable, executes to empty output) |

Backend fingerprinting (from response headers and the `lib/` 403 page): **istio-envoy → Apache/2.4.69 (Debian), port 8080 → PHP 8.4.27**. Session handling via `PHPSESSID` (`HttpOnly`, `SameSite=Strict`).


### 4.2 Security mechanisms observed

Response headers on `challenge.php`:

```http
content-security-policy: default-src 'none'; script-src 'nonce-<random>' 'self';
  style-src 'nonce-<random>'; connect-src 'self'; img-src 'self' data:;
  base-uri 'none'; object-src 'none'; form-action 'self'; frame-ancestors 'self'
x-content-type-options: nosniff
referrer-policy: same-origin
cross-origin-opener-policy: same-origin
```

Implications for exploitation:

- Inline scripts and **event handlers** are dead (no `'unsafe-inline'`) — classic `onerror=` payloads are useless.
- `javascript:` URLs, `<iframe srcdoc>`, `<base>` override — all dead (`base-uri 'none'`, CSP).
- `x-content-type-options: nosniff` — no sniffing a HTML endpoint (e.g. `challenge.php` itself) as a script.
- **`script-src 'self'` is the one open door**: the page may loadScripts from its own origin. The question becomes *which same-origin URL can serve attacker-chosen JavaScript*.

### 4.3 Input parameter & sink analysis

The only parameter is `person`. Two reflection paths exist:

1. **Server-side (safe):** escaped via `htmlspecialchars`-style encoding into the search box `value="…"` attribute and, for unknown names, into `<mark>…</mark> not found`.
2. **Client-side (the real story):** the page copies the *raw* decoded parameter into the DOM:

```javascript
var note = new URLSearchParams(location.search).get('person') || '';
...
var holder = document.createElement('template');
holder.innerHTML = String(note);                       // parse attacker HTML in template
// strip script/iframe/object/embed elements
// strip any attribute matching /^on/i
profile.innerHTML = holder.innerHTML                   // re-serialise + re-parse into live DOM
                     + '<p class="status"> not found</p>';
```

Sinks identified in the page's boot script (IIFE):

- `innerHTML` assignment (XSS sink), `decodeURIComponent` on an attribute value, `document.createElement('script')` + `src` assignment (**dynamic script insertion — the execution sink**), and a global `window.alert` override that chains to `fetch('/reveal.php', {method:'POST', headers:{'X-Registry-Check':'1'}})` and writes the response into `#vault`.

### 4.4 The hidden gate

The boot script performs DOM lookups for elements that **do not exist anywhere in the server-rendered page**:

```javascript
var marker = document.getElementById('record-anchor');
var latch  = document.getElementById('archive-latch');
...
if (!marker || !latch || latch.getAttribute('data-key') !== 'river-lantern') return;
var endpoint = marker.getAttribute('data-index');
if (typeof endpoint !== 'string' || endpoint.indexOf('/') !== 0) return;
endpoint = decodeURIComponent(endpoint);
if (endpoint !== '/echo.php?channel=echo&listener=alert(document.domain)//') return;
var loader = document.createElement('script');
loader.src = endpoint;
document.head.appendChild(loader);
```

If both elements exist with the exact attribute values, the page **builds and loads a same-origin script from `echo.php` with a pinned query**. Since the attacker fully controls the DOM into which the `person` value is parsed, these `getElementById` calls resolve to attacker-supplied elements — this is the crux of the challenge.

### 4.5 `echo.php` behaviour — the second door

`/echo.php?channel=echo&listener=alert(document.domain)//` responds `403` (empty body, generated **after** `session_start()` — PHP session headers present) for every request variant tested until the loading page's payload is in the expected thematic form. Differential testing (Section 6.4) shows the endpoint validates the *shape* of the `person` payload associated with the loading page — the exact mechanism is server-internal (most plausibly a check on the `Referer`-visible payload, or on server state set when the canonical payload was rendered); what was verified black-box is that **shape is the discriminator** and only the thematic canonical markup passes.

---

## 5. Vulnerability & Bypass Analysis

### 5.1 Vulnerability identification

**DOM-based XSS via unsafe `innerHTML` assignment of a URL-controlled value, escalated through DOM clobbering of the page's internal gate (`CWE-79` DOM XSS; the gate-abuse aspect is a client-side trust-boundary failure — the page verifies security state using data an attacker can influence).**

### 5.2 Technical explanation — why the server-side escaping does not matter

` htmlspecialchars` (server) protects the two *server-rendered* reflections. But the DOM sink does not consume the server's output — it consumes `location.search` directly. Escaping stops the value from becoming markup **once**; the second, JavaScript-side evaluation path re-introduces it. This is the classic "double interpretation" failure and is exactly what the official tip hinted at: *"The PHP side carefully wraps the name, but later the browser reads the same person value again. Ask yourself: where does text stop being 'text' and start becoming markup?"*

### 5.3 The sanitiser — what survives

The sanitiser is a `<template>`-parse pass that removes:

- elements: `script`, `iframe`, `object`, `embed`
- attributes: anything matching `/^on/i`
- **everything else passes untouched** — including `id`, `data-*`, `href`, `formaction`, custom elements, and namespace-confusing tags (`svg`, `math`, `style`, `noscript`, `form`).

For this challenge the required primitive is simply *"exist with these ids and attributes"* — which survives trivially.

### 5.4 The bypass — DOM clobbering of a scripted trust gate

The gate's design assumption is *"`getElementById('record-anchor')` can only ever return **our** trusted element."* That assumption is unsound: after the injection, `getElementById` resolves to attacker markup. The attacker cannot choose *what code runs* (the `endpoint` is pinned by an exact-equality check), but can choose **that the gate fires at all** — and the pinned `echo.php` is precisely the endpoint the challenge author black-boxed as "the thing that returns the alert payload".

The CSP analysis completes the picture: inline execution is impossible, but `script-src 'self'` legitimises the dynamically-inserted same-origin script (which needs no nonce, since it is inserted via DOM APIs by an already-running script). `echo.php` is the only same-origin endpoint that returns real JavaScript — making it the design compromise between "CSP-proof" and "exploitable".

### 5.5 The server-side second door — payload-shape validation

Differential testing during the solve:

| Payload variant | Client gate | `echo.php` |
|---|---|---|
| `<div id="record-anchor" …></div><div id="archive-latch" …></div>` (siblings) | ✅ loader created | ❌ 403 |
| `<div id='record-anchor' …></div><div id='archive-latch' …></div>` (single quotes) | ✅ loader created | ❌ 403 |
| `<div id="archive-latch" …><a id="record-anchor" …>signal</a></div>` (**canonical form**) | ✅ loader created | ✅ **200** |

The server requires the **thematic canonical markup** (mechanism most plausibly a `Referer`-based or session-based check — see §4.5): the `record-anchor` as a genuine **anchor** `<a>` element (a pun on the element id), **nested inside** the `archive-latch` div, carrying the text **`signal`** (the "radio keeper" theme). This two-door design — client shape-check plus server payload-shape check — is what makes the challenge interesting.

---

## 6. Exploitation & Payload Breakdown

### 6.1 Step-by-step exploitation

1. **Craft the URL** with the person parameter containing the canonical payload (URL-encoded).
2. **Victim opens the link.** Server escapes the value into `<mark>…</mark> not found` (harmless), but the client script re-reads the raw parameter for the injection path.
3. **Injection survives the sanitiser** — no `script`/`on*` is used; only `div`, `a`, `id`, `data-*`.
4. **DOM clobbering completes:** `getElementById('archive-latch')` and `getElementById('record-anchor')` now resolve to injected elements whose attributes pass every equality check.
5. **The page self-loads the gadget:** the boot script appends `<script src="/echo.php?channel=echo&listener=alert(document.domain)//">` to `<head>`.
6. **`echo.php` accepts the request** (200) because the payload associated with the visit is in the canonical shape the server expects, and returns the echoed listener as executable JavaScript: `alert(document.domain)//`.
7. **`alert()` fires** — a dialog appears on `challenge-brp.challenges.intigriti.io`; the page's **overridden** `alert` handler continues (once the dialog is dismissed) and POSTs `/reveal.php` with `X-Registry-Check: 1`.
8. **Flag capture:** the response is written into the hidden `#vault`: `ARCHIVE OPEN: INTIGRITI{f2cb05a5-5cc1-4d1d-b7cd-084306cbd5a0}`.

### 6.2 Final payload

```html
<div id="archive-latch" data-key="river-lantern"><a id="record-anchor" data-index="/echo.php?channel=echo&listener=alert(document.domain)//">signal</a></div>
```

Full URL:

```
https://challenge-brp.challenges.intigriti.io/challenge.php?person=%3Cdiv%20id%3D%22archive-latch%22%20data-key%3D%22river-lantern%22%3E%3Ca%20id%3D%22record-anchor%22%20data-index%3D%22%2Fecho.php%3Fchannel%3Decho%26listener%3Dalert(document.domain)%2F%2F%22%3Esignal%3C%2Fa%3E%3C%2Fdiv%3E
```

### 6.3 Payload breakdown

| Fragment | Purpose |
|---|---|
| `<div id="archive-latch" data-key="river-lantern">` | Satisfies `getElementById('archive-latch')` and the `data-key === 'river-lantern'` equality check |
| `<a id="record-anchor" data-index="/echo.php?channel=echo&listener=alert(document.domain)//">` | Satisfies `getElementById('record-anchor')` and the exact `data-index` equality (post-`decodeURIComponent`). Using a real `<a>` **anchor** element, nested inside the latch, is what passes the server-side shape check (plain `div`s are rejected with 403) |
| `>signal<` | Text content required by the thematic canonical form accepted by `echo.php` |
| `&listener=alert(document.domain)//` | The JS `echo.php` returns; the trailing `//` is almost certainly intended to comment out any suffix the server may append after the echoed value |
| **Why no `<script>`/`on*`?** | The sanitiser would remove them — and CSP would block them anyway. The exploit needs neither: the page's own trusted code does all execution work after being clobbered |

### 6.4 Flag capture evidence

Observed in a fresh-profile Chromium session on the live challenge page (DOM + Performance API):

```javascript
document.getElementById('vault').textContent
// → "ARCHIVE OPEN: INTIGRITI{f2cb05a5-5cc1-4d1d-b7cd-084306cbd5a0}"

performance.getEntriesByType('resource')
  .filter(e => e.name.includes('echo.php'))
  .map(e => e.responseStatus)
// → [200]
```

The HTTP-level sequence (DevTools → Network): `challenge.php?person=<payload>` (200) → `echo.php?channel=echo&listener=alert(document.domain)//` (200, JavaScript) → `alert` dialog on origin → `POST /reveal.php` with `X-Registry-Check: 1` (200) → vault populated with the flag.

---

## 7. Root Cause & Remediation

### 7.1 Root cause

1. **Primary:** a URL-controlled value is assigned to `innerHTML` after a home-grown sanitiser — a source-to-sink data flow the server-side output encoding never covers.
2. **Escalation root:** the application's internal state machine (the two-door gate) is implemented with `document.getElementById` over a DOM the attacker can fully populate. DOM *state* was treated as application *trust*.
3. **Design amplifier:** CSP `script-src 'self'` — correct in intent — turns any same-origin JS-echoing endpoint into an execution gadget once the gate is clobberable.

### 7.2 Why the existing controls failed

| Control | Why it did not stop the chain |
|---|---|
| Server-side output escaping | Protects only the server-rendered reflection; the client re-reads the raw query value |
| Client-side sanitiser (`template` pass) | Allow-list too narrow (only strips 4 element types + `on*`); leaves `id`/`data-*`, the exact attributes the clobber needs |
| Strict CSP (nonces, no inline) | Correct but incomplete: `'self'` + attacker-direction of an internal code path = script execution without any inline code |
| `echo.php` gate | Confirms a *request property the attacker controls* (the Referer's payload shape) instead of server-side state — an attacker can simply produce the expected shape |

### 7.3 Recommended secure implementation

1. **Never assign query-derived strings with `innerHTML`.** `textContent` (or a hardened, dependency-managed sanitiser) for any user data; treat `getElementById` results as untrusted in security decisions.
2. **Move gates out of the DOM.** Authoritative state belongs in the session/server (or a signed, integrity-checked client token), never in attribute values of parseable content.
3. **If a DOM-based gate is unavoidable:** namespace it (`id="app-internal-…"`) and have the sanitiser strip `id`/`data-*` attributes colliding with the application's internal namespace — clobbering then fails structurally.
4. **Sanitiser hygiene:** strip not only `on*` and known-dangerous elements but also event-capable vectors in foreign content (`svg`/`math`), and validate the *serialised* output (re-parse and diff) to defeat parsing-context mismatches.
5. Keep the existing headers (they are genuinely good) — CSP with `'self'` scripting is acceptable **only** alongside the above, because same-origin endpoints otherwise become attacker-directed gadgets.

---

## 8. Key Takeaways

- **Escaping ≠ safety.** A value can be escaped in one rendering context and still be raw in another path (server reflection vs. client re-read). Always trace *all* consumption points of user input, not just the visible response.
- **`<template>` parses with scripting disabled; `innerHTML` on the live DOM does not.** Sanitising "once" on a differently-parsed tree and then re-serialising is a subtle but critical hand-off — trust boundaries exist between parse contexts, not just between server and client.
- **DOM clobbering is a gate-override primitive, not just a variable-pollution trick.** Any client-side security decision that starts with `document.getElementById`/`querySelector` on attacker-parseable markup is attacker-owned.
- **`script-src 'self'` is only as strong as your same-origin endpoints.** Same-origin files that echo attacker input as JS (or might in the future) are living gadgets; audit them as attack surface.
- **Methodology hits that mattered here:** reading the client script fully before fuzzing; treating HTTP `403`-vs-`200`/empty-body differences as an oracle with *strict* detection (empty 403s masquerade as "success" if you only grep for failure text); differential testing of payload shapes to fingerprint server-side validators; `performance.getEntriesByType('resource')` (`responseStatus`) as a script-load oracle when the loader's status isn't otherwise visible.

---

## 9. References

- OWASP — *DOM Based XSS Prevention Cheat Sheet* — https://cheatsheetseries.owasp.org/cheatsheets/DOM_Based_XSS_Prevention_Cheat_Sheet.html
- PortSwigger Web Security Academy — *DOM clobbering* — https://portswigger.net/web-security/dom-based/dom-clobbering
- PortSwigger Web Security Academy — *DOM-based XSS* — https://portswigger.net/web-security/cross-site-scripting/dom-based
- CWE-79 — Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') — https://cwe.mitre.org/data/definitions/79.html
- CWE-345 — Insufficient Verification of Data Authenticity (client-trust analogue) — https://cwe.mitre.org/data/definitions/345.html
- MDN — `Element.innerHTML` (security notes) — https://developer.mozilla.org/en-US/docs/Web/API/Element/innerHTML
- MDN — Content Security Policy (`script-src`, nonces, `'self'`) — https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/script-src
- HTML Living Standard — scripting-flag difference for `noscript`/template parsing — https://html.spec.whatwg.org/multipage/scripting.html
- Michał Bentkowski — innerHTML/template parsing-context sanitation research (`<noscript>`-class mXSS insights) — https://research.securitum.com
- Official challenge tips post — https://x.com/intigriti/status/2115413762043740246 *(tip 1: "The first door is not on the server … where does text stop being 'text' and start becoming markup?")*

---

**Author:** Md Al Wakil Islam
**Platform:** Intigriti CTF
**Date:** 2026-10-30
