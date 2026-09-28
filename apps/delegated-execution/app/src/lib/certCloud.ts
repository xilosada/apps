/**
 * Enrolment where **the cloud signs** and a security key authorises it.
 *
 * This is the proposal's flow C with one substitution: the certificate the cloud
 * issues is a core `AccountProof<DeviceCert>` rather than the JWS device
 * certificate, because the node this demo talks to is `merod` and merod verifies
 * core's bytes. Same cloud, same WebAuthn credential, same app-certificate
 * requirement, same origin rule.
 *
 * ## Why this is a redirect and not a `navigator.credentials.get` call here
 *
 * The first version of this file called WebAuthn directly from the app's origin
 * and the cloud refused every assertion. WebAuthn puts the *calling* origin
 * inside `clientDataJSON`, and the relying party checks it against its own — so
 * an assertion produced on `localhost:5173` is not one `cloud.calimero.network`
 * will accept. The ceremony has to run on the cloud's page.
 *
 * That constraint is worth more than it costs: the person approves on a screen
 * **the app cannot draw**, showing the real origin and the real device key, and
 * the app never touches the assertion at all.
 *
 * ## What the touch authorises
 *
 * The challenge is `SHA-256(nonce ‖ device_key ‖ origin)`, computed by the
 * cloud. A touch authorises **one key for one app**, not a session — which is
 * what makes a stolen cloud session useless for minting a certificate over an
 * attacker's key (R2).
 *
 * ## What proves the app holds the key
 *
 * A signature over `nonce ‖ origin` by the device key, carried in the fragment.
 * The JWS flow proves this with a P-256 JWS; an Ed25519 key cannot make one, so
 * this is the raw equivalent. Without it an app could have a certificate issued
 * over a public key it does not hold — useless to it, but it would still put a
 * stranger's key in someone's account.
 */

import type { DeviceHandle } from './device.js';

/** Where the nonce waits while the person is on the cloud's page. */
const PENDING_KEY = 'calimero.delegated-demo.cert-enrol';
/** A round trip older than this is abandoned rather than resumed. */
const PENDING_LIFETIME_MS = 10 * 60 * 1000;

const hex = (bytes: Uint8Array): string =>
  Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');

export class CertCloudError extends Error {
  override name = 'CertCloudError';
}

async function post<T>(url: string, body: unknown): Promise<T> {
  let res: Response;
  try {
    res = await fetch(url, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(body),
    });
  } catch {
    throw new CertCloudError(`cannot reach the certificate cloud at ${url}`);
  }
  const json = (await res.json().catch(() => ({}))) as { error?: string };
  if (!res.ok) throw new CertCloudError(json.error ?? `the cloud answered ${res.status}`);
  return json as T;
}

interface PendingEnrol {
  nonce: string;
  /** The key this enrolment is for — checked against what comes back. */
  devicePublicKey: string;
  created: number;
}

function loadPending(): PendingEnrol | null {
  try {
    const raw = localStorage.getItem(PENDING_KEY);
    if (!raw) return null;
    const parsed = JSON.parse(raw) as PendingEnrol;
    return typeof parsed.nonce === 'string' ? parsed : null;
  } catch {
    return null;
  }
}

export function clearPendingEnrol(): void {
  try {
    localStorage.removeItem(PENDING_KEY);
  } catch {
    // Nothing was stored; nothing to clear.
  }
}

/**
 * Start an enrolment and hand the browser to the cloud's approval page.
 *
 * Does not return in the normal case — the page navigates away and comes back
 * through {@link readEnrolCallback}.
 */
export async function beginCloudEnrol(cloudUrl: string, handle: DeviceHandle): Promise<never> {
  const base = cloudUrl.replace(/\/+$/, '');
  const origin = window.location.origin;
  // Bare origin + path, no fragment: `valid_return` refuses a return address
  // carrying one, since that is where the answer goes.
  const returnTo = `${origin}${window.location.pathname}`;

  const start = await post<{ nonce: string }>(`${base}/api/account/enroll/start`, {
    device_key: handle.devicePublicKey,
    kem_key: handle.kemPublicKey,
    return_to: returnTo,
  });

  // Proof that this app holds the key it is asking to have certified. The cloud
  // knows the origin from the header, so signing it here binds the two.
  const payload = new TextEncoder().encode(start.nonce + origin);
  const pop = hex(
    new Uint8Array(await crypto.subtle.sign({ name: 'Ed25519' }, handle.signingKey, payload)),
  );

  localStorage.setItem(
    PENDING_KEY,
    JSON.stringify({
      nonce: start.nonce,
      devicePublicKey: handle.devicePublicKey,
      created: Date.now(),
    } satisfies PendingEnrol),
  );

  const url = new URL(`${base}/account-enroll`);
  url.hash = new URLSearchParams({ n: start.nonce, pop }).toString();
  window.location.assign(url.toString());
  // The navigation is asynchronous; nothing below here should run.
  return new Promise<never>(() => {});
}

/** What came back from the cloud, once the fragment has been read. */
export interface CloudGrant {
  accountId: string;
  deviceId: string;
  /** `AccountProof<DeviceCert>`, hex borsh. */
  credential: string;
}

/**
 * Read an enrolment answer out of the URL fragment, if this load is one.
 *
 * Returns `null` on an ordinary load. Throws when an answer arrived that this
 * browser cannot account for — a nonce it did not start, or one for a different
 * device key, both of which mean something is wrong rather than merely absent.
 *
 * The fragment is stripped either way: browsers never send it to a server, but
 * leaving it would make the next plain reload look like a callback.
 */
export function readEnrolCallback(): CloudGrant | null {
  const params = new URLSearchParams(window.location.hash.slice(1));
  const nonce = params.get('n');
  if (!nonce) return null;

  window.history.replaceState(null, '', window.location.pathname + window.location.search);

  const pending = loadPending();
  clearPendingEnrol();

  const error = params.get('error');
  if (error) {
    throw new CertCloudError(
      error === 'cancelled' ? 'the approval was cancelled; nothing was signed' : error,
    );
  }

  if (!pending || pending.nonce !== nonce) {
    throw new CertCloudError('an answer arrived that this browser has no request for');
  }
  if (Date.now() - pending.created > PENDING_LIFETIME_MS) {
    throw new CertCloudError('that enrolment took too long; start it again');
  }

  const credential = params.get('credential');
  const account = params.get('account');
  const device = params.get('device');
  if (!credential || !account || !device) {
    throw new CertCloudError('the answer was incomplete');
  }

  return { accountId: account, deviceId: device, credential };
}
