// Browser stand-in for Node's crypto module. mongosh uses createHash('md5')
// only for legacy MONGODB-CR password digests in user management helpers,
// which the portal does not support.
export function createHash(): never {
  throw new Error('Password digest helpers are not supported in the portal shell');
}

export function randomBytes(n: number): Uint8Array {
  return globalThis.crypto.getRandomValues(new Uint8Array(n));
}

export default { createHash, randomBytes };
