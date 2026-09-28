/**
 * A device key this page can use and cannot read.
 *
 * The demo's original identity keeps an ed25519 secret — and the account root —
 * as hex in `localStorage`, and says plainly that a product must not. This
 * module is the other half of that sentence: the signing key is generated
 * non-extractable, lives in IndexedDB as a `CryptoKey`, and never exists as
 * bytes in script memory. Injected script on this origin can still *spend*
 * warrants while the page is open, which is the residual the design accepts;
 * what it can no longer do is walk away with the identity.
 *
 * ## What is not here, deliberately
 *
 * **The account root.** A root in the browser was the compromise; keeping it
 * non-extractable would not fix it, because a certificate has to be signed
 * somewhere the root actually is. So this module holds no root and mints no
 * certificate: it produces a public key, and something else — a CLI holding the
 * root offline, or an Auth app holding it in hardware — signs the
 * `AccountProof<DeviceCert>` that comes back as {@link EnrolledDevice.credential}.
 *
 * **A re-derivable public key.** `crypto.subtle.exportKey` refuses a
 * non-extractable private key, and mero-js's `derivePublicKey` needs an
 * extractable one, so the public half is captured at generation and stored
 * beside the handle. Losing it means losing the ability to name the key, not
 * just to use it.
 */

import { signerFromCryptoKey, type Signer } from '@calimero-network/mero-js';

const DB_NAME = 'calimero.delegated-demo';
const STORE = 'kv';
const DEVICE_KEY = 'device.key';
const DEVICE_META = 'device.meta';

/** What travels, and what a warrant names. No secret appears here. */
export interface EnrolledDevice {
  /** The account these writes are attributed to, 64 hex. */
  accountId: string;
  /** The device's replica id, 64 hex. */
  deviceId: string;
  /** The device's ed25519 public key, 64 hex. */
  devicePublicKey: string;
  /**
   * The `AccountProof<DeviceCert>`, hex borsh, signed by a root this browser
   * never saw. Until it arrives the key is real but speaks for nobody.
   */
  credential: string;
}

/** The private half: usable, unreadable, and never serialised. */
export interface DeviceHandle {
  signingKey: CryptoKey;
  devicePublicKey: string;
  /**
   * The X25519 key a wrapped group key would be delivered to, hex.
   *
   * A device certificate covers two keys, and this client never receives a
   * group key — it reads through a session and writes through a relay, both of
   * which hold the key material. The X25519 half is generated anyway, because
   * substituting a placeholder produces a certificate that verifies today and
   * strands the device the moment anyone tries to deliver it a key.
   */
  kemPublicKey: string;
  /**
   * The X25519 private half, non-extractable.
   *
   * Kept now, where it used to be dropped as "a secret nothing reads". The
   * portal enrolment flow reads it: the confirmation code you type is checked
   * against an X25519 secret derived between this key and the approver's
   * ephemeral key, so **only this page can check the code**. That is what stops
   * a mailbox choosing which approval you accept — and it only works if the
   * private half survives.
   *
   * Optional because a device enrolled before this field existed does not have
   * one. Such a device still signs, reads and writes; it simply cannot do a
   * portal enrolment, and the panel says so rather than failing obscurely.
   */
  kemPrivateKey?: CryptoKey;
  /**
   * 16 random bytes, hex, fixed at generation.
   *
   * Covers the `DeviceId` the account root mints for this device, so the same
   * browser asking twice is recognisably the same device rather than a second
   * one. Optional for the same reason as {@link DeviceHandle.kemPrivateKey}.
   */
  deviceNonce?: string;
}

export class UnsupportedBrowserError extends Error {
  override name = 'UnsupportedBrowserError';
  constructor(algorithm: string) {
    super(
      `this browser's WebCrypto has no ${algorithm}, which a device key needs. ` +
        'Chrome 137+, Firefox 130+ or Safari 17+.',
    );
  }
}

function idb<T>(mode: IDBTransactionMode, work: (store: IDBObjectStore) => IDBRequest | void): Promise<T> {
  return new Promise((resolve, reject) => {
    const open = indexedDB.open(DB_NAME, 1);
    open.onupgradeneeded = () => open.result.createObjectStore(STORE);
    open.onerror = () => reject(open.error);
    open.onsuccess = () => {
      const db = open.result;
      const tx = db.transaction(STORE, mode);
      const req = work(tx.objectStore(STORE));
      tx.oncomplete = () => {
        db.close();
        resolve((req && 'result' in req ? (req.result as T) : undefined) as T);
      };
      tx.onerror = () => {
        db.close();
        reject(tx.error);
      };
    };
  });
}

function hex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

/**
 * Generate this browser's device key, or return the one it already has.
 *
 * A `CryptoKey` survives IndexedDB by structured clone, so the handle is stored
 * directly — there is no serialisation step that could leak the private half,
 * because there is no representation of it to leak.
 */
export async function deviceHandle(): Promise<DeviceHandle> {
  const existing = await idb<DeviceHandle | undefined>('readonly', (s) => s.get(DEVICE_KEY));
  if (existing) return existing;

  let pair: CryptoKeyPair;
  try {
    // `extractable: false` on the pair: the private half can never be exported,
    // which is the entire difference between this and the demo's hex secret.
    pair = (await crypto.subtle.generateKey({ name: 'Ed25519' }, false, ['sign', 'verify'])) as CryptoKeyPair;
  } catch {
    throw new UnsupportedBrowserError('Ed25519');
  }

  // The public half is exportable even when the private half is not, but only
  // while we hold the pair — so capture it now rather than re-deriving later.
  const raw = new Uint8Array(await crypto.subtle.exportKey('raw', pair.publicKey));

  let kem: CryptoKeyPair;
  try {
    // `extractable: false` on the delivery key too. The private half is used —
    // see `kemPrivateKey` — but only through `deriveBits`, never read.
    kem = (await crypto.subtle.generateKey({ name: 'X25519' }, false, ['deriveBits'])) as CryptoKeyPair;
  } catch {
    throw new UnsupportedBrowserError('X25519');
  }
  const kemRaw = new Uint8Array(await crypto.subtle.exportKey('raw', kem.publicKey));

  const handle: DeviceHandle = {
    signingKey: pair.privateKey,
    devicePublicKey: hex(raw),
    kemPublicKey: hex(kemRaw),
    kemPrivateKey: kem.privateKey,
    deviceNonce: hex(crypto.getRandomValues(new Uint8Array(16))),
  };
  await idb('readwrite', (s) => s.put(handle, DEVICE_KEY));
  return handle;
}

/** The public record of an enrolled device, if this browser has one. */
export async function enrolled(): Promise<EnrolledDevice | null> {
  const found = await idb<EnrolledDevice | undefined>('readonly', (s) => s.get(DEVICE_META));
  return found ?? null;
}

/**
 * Record what enrollment returned.
 *
 * Refuses a credential for a different key: a certificate that certifies some
 * other device would verify perfectly and vouch for a key this browser cannot
 * sign with, which surfaces later as an unspendable warrant.
 */
export async function recordEnrollment(device: EnrolledDevice): Promise<void> {
  const handle = await deviceHandle();
  if (device.devicePublicKey !== handle.devicePublicKey) {
    throw new Error('that credential certifies a different device key than this browser holds');
  }
  await idb('readwrite', (s) => s.put(device, DEVICE_META));
}

/**
 * The handle as something mero-js can sign with.
 *
 * This is the seam the whole app turns on. mero-js used to take 32 hex bytes
 * everywhere, so a key that cannot be exported could not be used with it at all
 * — and this app carried its own copies of core's warrant and login-statement
 * encodings to work around that. `Signer` removes the reason for those copies:
 * the library does the bytes, this module supplies a key it cannot read.
 *
 * The public half is passed explicitly because a non-extractable private key
 * cannot produce it — it was captured when the key was generated.
 */
export async function deviceSigner(handle: DeviceHandle): Promise<Signer> {
  return signerFromCryptoKey(handle.signingKey, handle.devicePublicKey);
}

/** Forget the device entirely — the key included, since it cannot be re-derived. */
export async function forgetDevice(): Promise<void> {
  await idb('readwrite', (s) => s.delete(DEVICE_KEY));
  await idb('readwrite', (s) => s.delete(DEVICE_META));
}
