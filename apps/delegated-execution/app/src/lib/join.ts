/**
 * Claiming an invitation with a key this page cannot export.
 *
 * This is the one governance op a keyholder signs **for itself**. Everything
 * else on the hardened path is either a credential someone else issued (the
 * device certificate) or a per-request authorisation (a login statement, a
 * warrant). Membership is different: it changes replicated state, and the person
 * joining is the one who signs for it.
 *
 * ## The admitter carries; it does not decide
 *
 * A keyholder holds no node, so it cannot publish to the namespace topic. It
 * hands the signed op to an **admitter** — a node the invitation's signed body
 * names — which attaches its own `AdmitterEndorsement` and publishes.
 *
 * Three things make that safe to hand to a node you do not trust:
 *
 * - every peer checks `op.signer == credential.sign_pk`, so the admitter cannot
 *   substitute a different account, change the group or grant a role;
 * - the endorsement rides **outside** the joiner's signature and outside the
 *   op's id, so attaching one changes neither what was signed nor which op it is
 *   — which is also the only reason a keyholder can be admitted at all, since it
 *   cannot produce an endorsement itself;
 * - core lets a designated admitter carry **only a join**, not governance at
 *   large, so being named in `admitters` is not a licence to publish whatever it
 *   is handed.
 *
 * Its only power is to refuse, which is a liveness problem rather than an
 * authority one — and why an invitation naming several admitters is worth more
 * than one naming a single node.
 *
 * ## Parents are empty, and that is not an oversight
 *
 * A keyholder has no view of the namespace DAG and cannot name its heads. Empty
 * is the only thing it can honestly sign, and the direct-admission path exists
 * for exactly this caller. Worth knowing: mero-js warns that empty parents mean
 * "signed against an empty head", which is not the same as genesis — so whether
 * a namespace with existing governance history folds this op is a property of
 * the receive path, not of this code.
 */

import {
  createLocalStorageNonceSource,
  signMemberJoinOp,
} from '@calimero-network/mero-js';

import { deviceSigner, type DeviceHandle, type EnrolledDevice } from './device.js';
import { joinNonceStorageKey } from './storage.js';

export class JoinError extends Error {
  override name = 'JoinError';
}

/** What the admit endpoint reports back. */
export interface JoinResult {
  /**
   * Whether the op reached the namespace topic.
   *
   * Not whether you are a member: the admitter neither applies the op nor waits
   * for anyone who does. Membership lands when peers fold it, so a read is what
   * confirms this worked.
   */
  published: boolean;
}

/**
 * Turn an admit refusal into the thing to go and do about it.
 *
 * Each status has one dominant cause and they are unrelated, so a bare "HTTP
 * 403" sends people to the invitation when the real answer is usually which node
 * they sent it to.
 */
function explain(status: number, body: string): string {
  const detail = body ? `: ${body}` : '';
  switch (status) {
    case 400:
      return (
        `the node refused the op as malformed (400)${detail}. The signature covers the ` +
        'invitation exactly as sent, so a re-serialised or edited invitation fails here.'
      );
    case 403:
      return (
        `the node refused to carry this join (403)${detail}. Either it is not in the ` +
        'invitation’s signed `admitters` list — being reachable and being listed are not the ' +
        'same thing — or the invitation was rejected as expired or not the inviter’s to issue.'
      );
    case 409:
      return (
        `that node holds no device of its own, so it cannot endorse anyone (409)${detail}. ` +
        'Pick another admitter.'
      );
    default:
      return `the join was not published (HTTP ${status})${detail}`;
  }
}

/**
 * Sign a membership op for this device's account and hand it to an admitter.
 *
 * @param nodeUrl the admitter's base URL — any node the invitation names
 * @param namespaceId the namespace being joined, 64 hex
 * @param invitationJson the invitation exactly as the operator's node printed it
 */
export async function joinNamespace(
  nodeUrl: string,
  namespaceId: string,
  invitationJson: string,
  device: EnrolledDevice,
  handle: DeviceHandle,
): Promise<JoinResult> {
  let invitation: Parameters<typeof signMemberJoinOp>[0]['invitation'];
  try {
    invitation = JSON.parse(invitationJson) as typeof invitation;
  } catch (cause) {
    throw new JoinError(
      'That is not valid JSON. Paste the invitation exactly as the node printed it — ' +
        (cause instanceof Error ? cause.message : String(cause)),
    );
  }

  // A separate counter from the warrant one: they are different anti-replay
  // windows kept by different code, and sharing one would have each spend a
  // number the other then skips.
  const nonces = createLocalStorageNonceSource(joinNonceStorageKey(device.devicePublicKey));

  const signedOp = await signMemberJoinOp({
    namespaceId,
    member: device.accountId,
    invitation,
    credential: device.credential,
    // The point of this module: signed by a key that cannot be exported. Until
    // mero-js grew a signer this call needed 32 hex bytes in script memory.
    signer: await deviceSigner(handle),
    nonce: await nonces.next(),
  });

  const admitUrl = `${nodeUrl.replace(/\/+$/, '')}/admin-api/namespaces/${encodeURIComponent(
    namespaceId,
  )}/admit`;

  // No authentication: the signature IS the authorization, which is what lets a
  // keyholder present this to a node it has no relationship with.
  const response = await fetch(admitUrl, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
    body: JSON.stringify({ invitation, signedOp }),
  });

  const text = await response.text();
  if (!response.ok) throw new JoinError(explain(response.status, text.slice(0, 300)));

  const body = text ? (JSON.parse(text) as { data?: { published?: boolean } }) : {};
  return { published: body.data?.published === true };
}
