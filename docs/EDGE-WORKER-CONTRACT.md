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
- `tcp`: a non-empty status string
- `tls`: a TLS status string
- `sni`: the exact SNI value actually applied to the TLS handshake

The Worker must echo `sni` only after it has configured that value for the handshake.
Echoing the request value without applying it is not valid evidence.

## Collector acceptance rules

- A result ID outside the current batch is ignored.
- Missing or malformed TCP status is not credited.
- If the requested SNI differs from the endpoint hostname, an exact case-insensitive
  `sni` echo is mandatory.
- A legacy result without an `sni` field is accepted only when the intended SNI is
  the endpoint hostname.
- A mismatch leaves the node **not tested**; it is never counted as a verification
  failure and never causes the node to be removed.

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
