import { describe, expect, it, vi } from 'vitest';
import { apiErrorToDisplay, authorizeOp, type ConfirmDecision, type ConfirmRequest } from './broker';
import { ApiError } from '../api/client';

const yes = vi.fn<(r: ConfirmRequest) => Promise<ConfirmDecision>>(async () => ({ confirmed: true }));
const no = vi.fn<(r: ConfirmRequest) => Promise<ConfirmDecision>>(async () => ({ confirmed: false }));

describe('authorizeOp', () => {
  it('forwards ordinary reads without confirmation', async () => {
    const r = await authorizeOp('find', '{"db":"app","coll":"o"}', false, new Set(), no);
    expect(r).toEqual({ ok: true });
    expect(no).not.toHaveBeenCalled();
  });

  it('rejects operations outside the allowlist', async () => {
    for (const op of ['getNewConnection', 'authenticate', 'eval', '__proto__', 'constructor']) {
      const r = await authorizeOp(op, '{}', true, new Set(), yes);
      expect(r.ok, op).toBe(false);
    }
  });

  it('blocks writes for read-only roles before contacting the server', async () => {
    const r = await authorizeOp('insertOne', '{"db":"app","coll":"o","document":{}}', false, new Set(), yes);
    expect(r.ok).toBe(false);
    expect(yes).not.toHaveBeenCalled();
  });

  it('requires typed confirmation for drops and never remembers them', async () => {
    const confirm = vi.fn<(r: ConfirmRequest) => Promise<ConfirmDecision>>(async () => ({ confirmed: true, remember: true }));
    const remembered = new Set<string>();
    const r = await authorizeOp('dropCollection', '{"db":"app","coll":"orders"}', true, remembered, confirm);
    expect(r).toEqual({ ok: true, confirmHeader: 'dropCollection' });
    expect(confirm.mock.calls[0][0]).toMatchObject({ typeToConfirm: 'orders', allowRemember: false });
    await authorizeOp('dropCollection', '{"db":"app","coll":"orders"}', true, remembered, confirm);
    expect(confirm).toHaveBeenCalledTimes(2);
  });

  it('remembers bulk confirmations only when asked', async () => {
    const confirm = vi.fn<(r: ConfirmRequest) => Promise<ConfirmDecision>>(async () => ({ confirmed: true, remember: true }));
    const remembered = new Set<string>();
    await authorizeOp('deleteMany', '{"db":"app","coll":"o","filter":{}}', true, remembered, confirm);
    const r = await authorizeOp('deleteMany', '{"db":"app","coll":"o","filter":{}}', true, remembered, confirm);
    expect(r).toEqual({ ok: true, confirmHeader: 'deleteMany' });
    expect(confirm).toHaveBeenCalledTimes(1);
  });

  it('confirms destructive runCommand and reports cancellation', async () => {
    const r = await authorizeOp('runCommand', '{"db":"app","command":{"dropIndexes":"o","index":"a_1"}}', true, new Set(), no);
    expect(r.ok).toBe(false);
    const ok = await authorizeOp('runCommand', '{"db":"app","command":{"dropIndexes":"o","index":"a_1"}}', true, new Set(), yes);
    expect(ok).toEqual({ ok: true, confirmHeader: 'runCommand' });
    const ping = await authorizeOp('runCommand', '{"db":"app","command":{"ping":1}}', false, new Set(), no);
    expect(ping).toEqual({ ok: true });
  });

  it('rejects malformed arguments', async () => {
    expect((await authorizeOp('deleteMany', 'not json', true, new Set(), yes)).ok).toBe(false);
  });
});

describe('apiErrorToDisplay', () => {
  it('distinguishes portal policy errors from MongoDB errors', () => {
    expect(apiErrorToDisplay(new ApiError(403, 'operation_not_permitted', 'nope')).name).toBe('PortalPolicyError');
    expect(apiErrorToDisplay(new ApiError(403, 'mongo_unauthorized', 'not authorized', undefined, 13, 'Unauthorized'))).toMatchObject({
      name: 'MongoServerError',
      code: 13,
      codeName: 'Unauthorized',
    });
  });
});
