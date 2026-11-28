// FastNodes second-vantage prober.
// v3.4 — bounded concurrency, per-active-probe timeout, and blocked-address diagnostics.
//
// Auth: Cloudflare secret AUTH. Never put the token in source code.
// Maximum 25 targets per request; at most 4 probes run concurrently.
// Cloudflare allows up to 6 simultaneous outgoing connections per invocation.
// Raw TCP/TLS sockets remain open until the probe finishes, so this Worker leaves
// headroom instead of queueing 25 connections behind the platform limit.
//
// IMPORTANT:
// - Endpoint host and TLS SNI remain separate.
// - Custom SNI is passed through the TLS servername option.
// - SNI is echoed after TCP connects and the TLS attempt is configured.
// - TLS success requires secureConnect AND authorized === true.
// - Certificate verification is never disabled.
// - The 4-second timeout starts when a probe acquires a concurrency slot, not
//   while it waits in the local queue.

import { connect as tcpConnect } from "cloudflare:sockets";
import { connect as tlsConnect } from "node:tls";
import { isIP } from "node:net";

const MAX_TARGETS = 25;
const MAX_CONCURRENT_PROBES = 4;
const TIMEOUT_MS = 4000;
const MAX_REASON_LENGTH = 250;

export default {
  async fetch(request, env) {
    if (request.method !== "POST") {
      return json({ error: "POST only" }, 405);
    }

    // Fail closed if AUTH is missing or incorrect.
    if (
      typeof env.AUTH !== "string" ||
      env.AUTH.length === 0 ||
      request.headers.get("x-auth") !== env.AUTH
    ) {
      return json({ error: "auth" }, 401);
    }

    let body;
    try {
      body = await request.json();
    } catch {
      return json({ error: "bad json" }, 400);
    }

    if (!Array.isArray(body?.targets)) {
      return json({ error: "targets must be an array" }, 400);
    }

    const targets = body.targets.slice(0, MAX_TARGETS);
    if (targets.length === 0) {
      return json({ results: [] });
    }

    const results = await mapWithConcurrency(
      targets,
      MAX_CONCURRENT_PROBES,
      async (target) => {
        try {
          return await probe(target);
        } catch (error) {
          const message = String(error?.message ?? error);
          return {
            id: target?.id,
            tcp: classifyError(message),
            tls: target?.tls === true ? "failed" : null,
            reason: message.slice(0, MAX_REASON_LENGTH),
          };
        }
      }
    );

    return json({ results });
  },
};

// Run a bounded number of probes while preserving request order in the response.
// A probe timeout is started only after a worker takes that target from the queue.
async function mapWithConcurrency(items, concurrency, mapper) {
  const results = new Array(items.length);
  let nextIndex = 0;
  const workerCount = Math.min(items.length, Math.max(1, concurrency));

  const workers = Array.from({ length: workerCount }, async () => {
    while (true) {
      const index = nextIndex++;
      if (index >= items.length) return;
      results[index] = await mapper(items[index], index);
    }
  });

  await Promise.all(workers);
  return results;
}

// Validate a DNS hostname without accepting URLs, paths, whitespace, or other
// unexpected input.
function isValidHostname(host) {
  if (
    typeof host !== "string" ||
    host.length === 0 ||
    host.length > 253 ||
    host !== host.trim()
  ) {
    return false;
  }

  const normalized = host.endsWith(".") ? host.slice(0, -1) : host;
  if (!normalized || normalized.length > 253) return false;

  return normalized.split(".").every((label) =>
    label.length >= 1 &&
    label.length <= 63 &&
    /^[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?$/.test(label)
  );
}

function isValidHost(host) {
  return (
    typeof host === "string" &&
    host.length > 0 &&
    host.length <= 253 &&
    host === host.trim() &&
    (isIP(host) !== 0 || isValidHostname(host))
  );
}

function isValidSni(sni) {
  if (sni === undefined || sni === null) return true;

  if (
    typeof sni !== "string" ||
    sni.length === 0 ||
    sni.length > 253 ||
    sni !== sni.trim()
  ) {
    return false;
  }

  // IP literals are valid input but are not sent as TLS SNI hostnames.
  return isIP(sni) !== 0 || isValidHostname(sni);
}

async function probe(target) {
  const result = {
    id: target?.id,
    tcp: "error",
    tls: target?.tls === true ? "failed" : null,
    reason: null,
  };

  if (
    !target ||
    typeof target !== "object" ||
    Array.isArray(target) ||
    !Number.isInteger(target.id) ||
    !isValidHost(target.host) ||
    !Number.isInteger(target.port) ||
    target.port < 1 ||
    target.port > 65535 ||
    (target.tls !== undefined && typeof target.tls !== "boolean") ||
    !isValidSni(target.sni)
  ) {
    result.reason = "invalid target";
    return result;
  }

  const { host, port, tls } = target;

  try {
    if (tls === true) {
      await probeTls(host, port, target.sni, result);
    } else {
      await probeTcp(host, port, result);
    }
  } catch (error) {
    const message = String(error?.message ?? error);
    result.reason = message.slice(0, MAX_REASON_LENGTH);

    if (result.tcp !== "ok") {
      result.tcp = classifyError(message);
    }

    if (tls === true && result.tls !== "ok") {
      result.tls = "failed";
    }
  }

  return result;
}

// Plain TCP probe.
async function probeTcp(host, port, result) {
  let socket;

  try {
    socket = tcpConnect(
      { hostname: host, port },
      { secureTransport: "off" }
    );

    await withTimeout(socket.opened, TIMEOUT_MS);
    result.tcp = "ok";
  } finally {
    try {
      await socket?.close();
    } catch {
      // Ignore cleanup errors.
    }
  }
}

// TLS probe with endpoint host and SNI kept separate.
async function probeTls(host, port, requestedSni, result) {
  const effectiveSni =
    typeof requestedSni === "string" ? requestedSni : host;

  // SNI is a DNS hostname, not an IP literal.
  const sendSni = isIP(effectiveSni) === 0;

  await new Promise((resolve, reject) => {
    let socket;
    let timer;
    let settled = false;

    const finish = (error) => {
      if (settled) return;

      settled = true;
      clearTimeout(timer);

      if (socket) {
        socket.removeListener("connect", onTcpConnect);
        socket.removeListener("secureConnect", onSecureConnect);
        socket.removeListener("error", onError);
        socket.destroy();
      }

      if (error) reject(error);
      else resolve();
    };

    // TCP is established and TLS was configured with this SNI.
    // Report it even if the TLS handshake subsequently fails.
    const onTcpConnect = () => {
      result.tcp = "ok";
      if (sendSni) result.sni = effectiveSni;
    };

    // TLS handshake completed.
    const onSecureConnect = () => {
      result.tcp = "ok";

      // Explicitly require successful certificate authorization.
      if (socket.authorized !== true) {
        const authorizationError =
          socket.authorizationError || "certificate not authorized";

        result.tls = "failed";
        result.reason = String(authorizationError).slice(
          0,
          MAX_REASON_LENGTH
        );

        finish(new Error(result.reason));
        return;
      }

      result.tls = "ok";
      finish();
    };

    const onError = (error) => finish(error);

    timer = setTimeout(
      () => finish(new Error("timeout")),
      TIMEOUT_MS
    );

    try {
      const options = { host, port };

      // Apply requested SNI separately from endpoint hostname.
      if (sendSni) options.servername = effectiveSni;

      // Never disable certificate verification.
      socket = tlsConnect(options);

      socket.once("connect", onTcpConnect);
      socket.once("secureConnect", onSecureConnect);
      socket.once("error", onError);
    } catch (error) {
      finish(error);
    }
  });
}

// Promise timeout helper.
function withTimeout(promise, milliseconds) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(
      () => reject(new Error("timeout")),
      milliseconds
    );

    Promise.resolve(promise).then(
      (value) => {
        clearTimeout(timer);
        resolve(value);
      },
      (error) => {
        clearTimeout(timer);
        reject(error);
      }
    );
  });
}

// Normalize common network, policy, and TLS errors.
function classifyError(message) {
  return /proxy request failed.*cannot connect to the specified address|disallowed address/i.test(message)
    ? "blocked-address"
    : /refus/i.test(message)
      ? "refused"
      : /code 10[0-9]|cloudflare/i.test(message)
        ? "cf-blocked"
        : /tim(eout|ed ?out)/i.test(message)
          ? "timeout"
          : /dns|resolve|getaddrinfo|ENOTFOUND|EAI/i.test(message)
            ? "dns"
            : /tls|ssl|handshake|cert|authoriz/i.test(message)
              ? "tls-failed"
              : "error";
}

// JSON response helper.
function json(value, status = 200) {
  return new Response(JSON.stringify(value), {
    status,
    headers: {
      "content-type": "application/json",
    },
  });
}
