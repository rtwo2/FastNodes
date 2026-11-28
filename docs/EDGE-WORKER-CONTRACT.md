# Cloudflare edge Worker contract

The collector sends edge probes to the externally deployed Worker configured by the
GitHub Actions secrets `WORKER_URL` and `WORKER_AUTH`. The Worker source and its
deployment are not stored in this repository, so a collector-side change alone cannot
guarantee custom-SNI verification.

## Request

The collector sends a JSON object containing a `targets` array. Each target has:

- `id`: integer unique within the request batch
- `host`: endpoint hostname or IP address used for the TCP connection
- `port`: endpoint port
- `tls`: `true`
- `sni`: effective TLS server name; this may differ from `host`

The Worker must keep the endpoint address and TLS SNI separate. It must connect to
`host:port` and use `sni` as the TLS server name. It must not replace a custom SNI
with the endpoint hostname.

## Response

Return a JSON object with a `results` array. Each result must include:

- `id`: the exact target ID
- `tcp`: a non-empty status string; `ok` means the endpoint TCP connection was established
- `tls`: a TLS status string when the TLS outcome is known
- `sni`: the exact SNI value actually configured for the TLS handshake, when the handshake was reached and an SNI hostname was sent

The Worker must echo `sni` only after it has configured that value for the handshake.
Echoing the request value without applying it is not valid evidence. Do not invent an SNI
echo when the TCP connection did not establish or when no SNI hostname was sent.

A result whose `tcp` status is not `ok` is a connection/vantage outcome: the collector
records the reported connection error but leaves the node **not tested** by the edge TLS
stage. Missing SNI on such a result is expected and is not counted as an SNI-confirmation
failure. Once `tcp` is `ok`, the collector requires SNI confirmation for a custom SNI
before it evaluates the TLS outcome. A confirmed TLS handshake failure is a tested failure;
a pre-TCP connection failure is not.

## Collector acceptance rules

- A result ID outside the current batch is ignored.
- Missing or malformed TCP status is not credited.
- If the requested SNI differs from the endpoint hostname, an exact case-insensitive
  `sni` echo is mandatory.
- A legacy result without an `sni` field is accepted only when the intended SNI is
  the endpoint hostname.
- A mismatch leaves the node **not tested**; it is never counted as a verification
  failure and never causes the node to be removed.

## Controlled deployment test

The repository tests the collector's response validation rules, but it cannot prove that
the separately deployed Worker uses the requested SNI. The Worker source and deployment
are external to this repository; a successful CI run is not an end-to-end Worker test.

Use a controlled TLS endpoint that records the ClientHello SNI and exercise this matrix:

| Scenario | Expected Worker result | Collector interpretation |
|---|---|---|
| TCP succeeds; custom SNI is applied; TLS succeeds | `tcp: ok`, `tls: ok`, exact `sni` echo | Edge-verified |
| TCP succeeds; custom SNI is applied; TLS fails | `tcp: ok`, TLS failure, exact `sni` echo | Tested failure; not removed |
| TCP fails before TLS | Non-`ok` `tcp` status; no SNI echo | Not tested by edge TLS |
| TCP succeeds but SNI is absent or mismatched | Missing or mismatched `sni` | Not tested; never credited |

For the custom-SNI case, verify the recorded ClientHello rather than trusting an echoed
request field alone. Repeat the test after every Worker deployment. This is the only
way to prove that the external service actually applied the requested SNI.

## Deployment checklist

1. Update the external Worker to consume `target.sni` and apply it to the TLS socket.
2. Return the actual applied SNI in `results[].sni`.
3. Deploy the Worker before expecting custom-SNI edge results to be credited.
4. Run a controlled test with `host != sni`; verify the response echoes the requested
   SNI and that the TLS handshake is performed using it.
5. Keep `WORKER_AUTH` in GitHub Actions secrets and the Worker environment. Never
   commit the secret or embed it in the request body.

Until the external Worker is upgraded, custom-SNI targets may consume probe slots but
will remain unverified if the Worker returns a host-only or mismatched SNI result.
