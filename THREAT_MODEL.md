<!--
SPDX-License-Identifier: Apache-2.0

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
-->

# Threat Model — Apache CXF Fediz

## §1 Header

- **Project:** Apache CXF Fediz — a web-application **single sign-on** system implementing the
  **WS-Federation 1.2 Passive Requestor Profile** (and SAML-SSO), with **SAML 1.1 / 2.0 tokens**, role
  information carried as SAML `AttributeStatement`s, and a published WS-Federation metadata document
  *(documented — README)*. It has two deployable halves: an **Identity Provider (IdP)** that authenticates
  users and issues tokens (STS-backed), and **Relying-Party (RP) plugins** embedded in a protected web app
  that redirect unauthenticated users to the IdP and **validate the returned token** *(documented — `services/`,
  `plugins/`)*.
- **Modelled against:** `apache/cxf-fediz` `main`/HEAD (2026-05-31).
- **Status:** **DRAFT — v0, not yet reviewed by the CXF PMC.** Companion to the `apache/cxf` umbrella model;
  Fediz's SSO trust surface is distinct and modelled here. Produced via the `threat-model-producer` rubric
  (<https://gist.github.com/potiuk/da14a826283038ddfe38cc9fe6310573>).
- **Version binding / reporting / legend / advisories** as in the CXF model
  (<https://cxf.apache.org/security-advisories.html>). **Draft confidence:** ~12 documented / 0 maintainer /
  ~46 inferred. Each *(inferred)* routes to §14.

In SSO the security pivot is **token validation at the RP** and **token issuance at the IdP**, both around a
token that travels through the *untrusted* browser. Most of this model lives in §8/§9 around those two points.

## §2 Scope and intended use

Intended use *(documented)*: protect web applications by delegating authentication to a Fediz IdP via
WS-Federation/SAML-SSO; the RP plugin enforces "authenticated + has claims" before the app runs.

Caller roles:

- **End-user browser (untrusted)** — drives the redirect-based flow and carries the token between IdP and RP.
- **Relying Party (the protected app + plugin)** — trusts tokens it can validate against the configured IdP.
- **Identity Provider** — authenticates users, issues signed tokens, exposes login + metadata.
- **STS** — issues/validates the underlying SAML tokens (WS-Trust) for the IdP.
- **Deployer/operator** — configures IdP trust (signing certs), RP `wtrealm`/audience, allowed reply URLs,
  TLS, and the user/credential store. **Trusted; out of model as adversary (§3).**

**Component-family table:**

| Family | Entry point | Touches outside process | In model? |
| --- | --- | --- | --- |
| RP plugin — token processing | `plugins/core` (`saml`, `samlsso`, `processor`, `handler`) | browser-delivered token; IdP cert | **Yes** |
| RP plugin — container integration | tomcat/jetty/spring/websphere plugins | servlet request/session | **Yes** |
| IdP service — auth + token issuance | `services/` (IdP), login | network; user store; STS | **Yes** |
| STS / WS-Trust | STS service | crypto; user store | **Yes** |
| WS-Fed metadata publish | metadata endpoint | network | **Yes** |
| Examples / systests / packaging | `examples/`, `systests/`, `apache-fediz`, `etc/` | — | No → §3 |

## §3 Out of scope (explicit non-goals)

- **The operator/deployer as adversary** and pure misconfiguration (wrong IdP cert trust, audience left
  unset, TLS disabled) — Fediz provides the validation; configuring it correctly is the deployer's job
  (§10/§11) *(inferred)*.
- **The protected application's own logic and its use of the established identity** beyond what the plugin
  provides.
- **The user-credential store / external auth backends** the IdP delegates to.
- **`examples/`, `systests/`, packaging, and `etc/` sample configs** *(inferred)*.
- **The underlying CXF/WSS4J XML-signature stack internals** except as Fediz configures and invokes them
  (the CXF umbrella model covers those).

## §4 Trust boundaries and data flow

Two boundaries dominate:

1. **RP ← browser-delivered token (the critical one).** After IdP login the browser POSTs/redirects a
   `wresult`/SAMLResponse to the RP. These bytes are **fully attacker-influenceable** (the user controls
   their browser); the RP must treat the token as untrusted until it has verified: the **XML signature**
   against the configured IdP signing certificate; the **issuer**; the **audience/`wtrealm`** equals this RP;
   the **conditions/timestamps** (NotBefore/NotOnOrAfter, clock skew); **one-time use / replay**; and that
   the signature covers the asserted content (**anti-XSW**) *(inferred — `samlsso`/`processor`; specifics §14)*.
2. **IdP ← login + token request.** The IdP authenticates the user and issues a token bound to the
   requesting RP (`wtrealm`) with a reply address (`wreply`); it must validate the RP/realm and the reply
   URL (open-redirect / token-forwarding surface) and protect the login from CSRF/brute-force *(inferred)*.

WS-Fed flow parameters (`wa`, `wresult`, `wctx`, `wtrealm`, `wreply`, `wfresh`, `wreq`) are all
attacker-tamperable in the browser and must be validated, not trusted *(inferred)*.

**Reachability preconditions:** an RP-side finding is in-model if reachable from a crafted/replayed token or
flow parameter *before* the plugin establishes the security context; an IdP-side finding is in-model if
reachable from an unauthenticated request to login/metadata/token endpoints; misconfiguration-only outcomes
are `OUT-OF-MODEL` (§3/§5a).

## §5 Assumptions about the environment

- **Runtime:** JVM web apps in a servlet container (RP plugins integrate with Tomcat/Jetty/Spring/WebSphere)
  and a deployed IdP/STS *(documented)*.
- **Trust material:** the RP is configured with the IdP's signing certificate(s)/truststore; the IdP/STS hold
  signing keys *(inferred)*.
- **Transport:** TLS protects the browser↔IdP and browser↔RP legs; Fediz supports but the deployer enforces
  it *(inferred — wave-1)*.
- **Clocks:** IdP and RP clocks are roughly synchronized for `Conditions` validation (a skew window applies)
  *(inferred)*.
- **What Fediz does to its host (*(inferred)* — wave-2):** processes XML/SAML; performs crypto; reads
  configured truststores/keystores; the IdP talks to the STS and the user store; not assumed to execute host
  commands.

## §5a Build-time and configuration variants

| Knob (names *(inferred)*) | Effect | Default ruling needed |
| --- | --- | --- |
| RP signature requirement / trusted IdP certs | Whether unsigned/untrusted tokens are rejected | **Open (wave-1):** signature + trust mandatory by default? |
| Audience (`wtrealm`) restriction enforcement | Prevents token replay to a different RP | **Open (wave-1)** |
| Token replay cache (one-time-use) | Replay protection of consumed tokens | **Open (wave-1)** |
| Clock-skew window for `Conditions` | Forgiveness of timestamp validation | Confirm default |
| `wreply`/reply-URL validation at the IdP | Open redirect / token forwarding | **Open (wave-1)** |
| SAML XML secure-processing (DTD/entity off) | XXE/XML-DoS on token parse | Confirm inherited CXF defaults |
| TLS enforcement on the flow | Token confidentiality/integrity in transit | Deployer (§10) |

## §6 Assumptions about inputs

| Entry point | Parameter | Attacker-controllable? | Caller/deployer must enforce |
| --- | --- | --- | --- |
| RP plugin | `wresult` / SAMLResponse (the token) | **yes** (browser-delivered) | full signature + issuer + audience + conditions + replay + anti-XSW |
| RP/IdP | `wctx`, `wtrealm`, `wreply`, `wfresh`, `wreq`, `RelayState` | **yes** | validate realm; allow-list reply URLs; treat context as opaque |
| IdP login | username/password / external auth | **yes** | credential verification; CSRF; throttling |
| IdP metadata endpoint | request | **yes** | safe publication; no SSRF via metadata refs |
| RP/IdP config (truststore, realm, certs) | all keys | **no — deployer-trusted** | never sourced from a request |

## §7 Adversary model

- **Primary adversary:** an untrusted web user/browser who crafts, tampers with, or **replays** SAML tokens and
  WS-Fed parameters to an RP, or attacks the IdP login/token endpoints. Capabilities: submit arbitrary
  `wresult`/parameters, replay a previously valid token, attempt signature-wrapping, forge an assertion,
  redirect via a manipulated `wreply`.
- **Secondary:** a malicious or compromised RP requesting tokens it should not receive; a network MITM where
  TLS is absent.
- **Goals:** authenticate as another user / bypass authentication at the RP; have a token minted or forwarded
  to an attacker-controlled RP; escalate roles by injecting `AttributeStatement` claims; open-redirect a user.
- **Out of model:** the deployer/operator; anyone holding the IdP signing key or the configured truststore;
  the credential store internals.

## §8 Security properties the project provides

*(All *(inferred)* pending §14; symptom + severity per the rubric.)*

1. **RP token authenticity & integrity.** The RP accepts a token only if its XML signature verifies against a
   configured/trusted IdP certificate and the signature covers the asserted content (anti-XSW)
   *(inferred — load-bearing)*. *Symptom:* acceptance of an unsigned/forged/wrapped token ⇒ authentication
   bypass / impersonation. *Severity:* critical.
2. **Audience & freshness binding.** A token is accepted only if its audience/`wtrealm` matches this RP and its
   `Conditions` (NotBefore/NotOnOrAfter, within skew) hold; consumed tokens are replay-protected
   *(inferred)*. *Symptom:* cross-RP replay or replay of an expired/old token. *Severity:* critical.
3. **IdP token-issuance integrity.** The IdP issues tokens only for authenticated users and signs them; it
   binds the token to the requesting realm and validates the reply target *(inferred)*. *Symptom:* token minted
   without auth, or for/forwarded to the wrong RP. *Severity:* critical.
4. **Role/claim integrity.** Roles/claims come from the signed assertion, so a client cannot inject or elevate
   claims *(inferred)*. *Symptom:* privilege escalation via tampered `AttributeStatement`. *Severity:* critical.
5. **Safe token parsing.** Malformed SAML/XML yields a clean rejection, not XXE/DoS/crash (inherits CXF/WSS4J
   secure-XML defaults) *(inferred)*. *Symptom:* XXE/SSRF/OOM from a crafted token. *Severity:* critical.

## §9 Security properties the project does NOT provide

- **No security without correct trust configuration.** If the RP is not configured with the right IdP signing
  trust, or audience validation is disabled, token validation is only as strong as what's left *(inferred)*.
- **No defence against a compromised IdP signing key or a deployer who trusts a hostile IdP** (§3).
- **No transport security by itself** — without TLS the token is interceptable/replayable on the wire.
- **The protected app must still authorize** beyond "authenticated"; Fediz establishes identity/claims, not
  the app's access-control policy.

**False friends:**

- *"The token is signed" is not "the token is valid for me now"* — signature alone, without audience +
  conditions + replay + anti-XSW checks, is the classic SAML-SSO bypass.
- *`wctx`/`RelayState` look like trusted state but are attacker-controlled* — treat as opaque, validate on return.
- *A published metadata document looks authoritative but is fetched over the same untrusted channels* — trust
  is anchored in configured certs, not in fetched metadata.

**Well-known attack classes to keep in view:** XML signature wrapping (XSW); unsigned-assertion / signature
-stripping acceptance; assertion replay and cross-audience replay; `Conditions`/clock-skew abuse; open redirect
via `wreply`; XXE/XML-DoS on token parse; CSRF on IdP login; recipient/audience confusion.

## §10 Downstream (deployer) responsibilities

- Configure the RP with the **correct IdP signing certificate(s)** and require signed tokens; **set the
  audience/`wtrealm`** so tokens for other RPs are rejected.
- Enforce **TLS** on every leg of the flow; keep IdP↔STS and truststore material protected.
- **Allow-list reply URLs** at the IdP (`wreply`) to prevent open redirect / token forwarding.
- Keep the **replay cache** and a sane **clock-skew window** enabled; sync clocks.
- Protect IdP login from CSRF/brute-force; secure the credential store.
- Stay on a supported line and watch <https://cxf.apache.org/security-advisories.html>.

## §11 Known misuse patterns

- Deploying an RP without configuring/validating the IdP signing trust (accepts any token).
- Disabling audience or conditions validation "to make it work".
- Running the flow over plain HTTP (token sniffable/replayable).
- Leaving `wreply` reply URLs unrestricted at the IdP (open redirect / token forwarding).
- Treating `wctx`/`RelayState` as trusted server state.

## §11a Known non-findings (recurring false positives)

*(v0 seed — the PMC will have the authoritative list — §14.)*

- **"Accepts a token" reports that assume validation is off** when the default requires signature + audience +
  conditions + replay — `KNOWN-NON-FINDING` / misconfig unless a *default* check is missing (then `VALID`).
- **Findings in `examples/` / `systests/` / sample configs** — out of scope (§3).
- **"No TLS"** against sample/local configs — deployer responsibility (§10).
- **Use of SAML 1.1** (legacy but supported) flagged generically — supported by design; only specific weak
  handling is a finding.

## §12 Conditions that would change this model

- A change to default signature/audience/conditions/replay enforcement in the RP.
- A new protocol (e.g. OIDC) or token type enabled by default.
- A change to `wreply` reply-URL validation or IdP login defaults.
- A change in the inherited CXF/WSS4J XML-security defaults.
- Any report not cleanly routable to a §13 disposition.

## §13 Triage dispositions

| Disposition | Meaning | Licensed by |
| --- | --- | --- |
| `VALID` | Violates a claimed property via an in-scope adversary/input *in a default/secure configuration*. | §8, §6, §7 |
| `VALID-HARDENING` | No §8 property broken, but a §11 misuse is easy enough to warrant a safer default/guard. | §11 |
| `OUT-OF-MODEL: trusted-input` | Requires control of deployer config / signing keys / truststore. | §6 |
| `OUT-OF-MODEL: adversary-not-in-scope` | Requires deployer / IdP-key / credential-store capability. | §7, §3 |
| `OUT-OF-MODEL: unsupported-component` | Lands in examples, systests, packaging, samples. | §3 |
| `OUT-OF-MODEL: non-default-build` | Only when the deployer disabled a validation control. | §5a |
| `BY-DESIGN: property-disclaimed` | Concerns a §9-disclaimed property (no security without trust config; identity ≠ app authorization). | §9 |
| `KNOWN-NON-FINDING` | Matches a §11a entry. | §11a |
| `MODEL-GAP` | Routes to none of the above → revise the model. | §12 |

## §14 Open questions for the maintainers

**Wave 1 — RP validation defaults (the SSO crux; §5a/§8):**
1. By default, does the RP **require a valid XML signature from a configured/trusted IdP cert** and reject
   unsigned/untrusted tokens? *Proposed:* yes, mandatory.
2. Are **audience/`wtrealm`** and **`Conditions`** (NotBefore/NotOnOrAfter + skew) enforced by default, and is
   a **replay cache** on by default? *Proposed:* all on by default.
3. Does the SAML processing defend **signature-wrapping (XSW)** by binding the verified signature to the
   consumed assertion/elements? *Proposed:* yes (via WSS4J/CXF).

**Wave 2 — IdP & redirect surface (§4/§8/§9):**
4. Does the IdP **validate `wreply` reply URLs** (allow-list) to prevent open redirect / token forwarding, and
   is its login **CSRF-protected and throttled**? *Proposed:* reply-URL allow-list configured per realm; login
   CSRF-protected.
5. How is the underlying **XML/SAML parsing hardened** against XXE/DoS — inherited from CXF/WSS4J secure
   defaults? *Proposed:* yes, inherited.

**Wave 3 — boundaries & §11a (§3/§9/§11a):**
6. Confirm the **deployer-misconfiguration** boundary (which "insecure" outcomes are `OUT-OF-MODEL`). *Proposed:*
   per §3/§11.
7. From the advisory history, what do scanners most often (re)report that the PMC considers a **non-finding**?
   (Seeds §11a.)

**Meta:**
8. Confirm this model lives in `apache/cxf-fediz` (linked from its `SECURITY.md`), separate from the
   `apache/cxf` umbrella. *Proposed:* yes.

## §15 Machine-readable companion

Deferred for v0; a `threat-model.yaml` can later encode the §6 trust table, §2/§3 scoping, §8 rows, §9 false
friends, §11a non-findings, and §13 dispositions.
