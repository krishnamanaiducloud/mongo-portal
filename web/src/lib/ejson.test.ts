import { describe, expect, it } from 'vitest';
import { detectBson, formatBytes, normalizeInput, num, shellToExtJSON, summarize } from './ejson';

describe('detectBson', () => {
  it('recognises canonical wrappers', () => {
    expect(detectBson({ $oid: '507f1f77bcf86cd799439011' })?.display).toBe('ObjectId("507f1f77bcf86cd799439011")');
    expect(detectBson({ $date: { $numberLong: '0' } })?.display).toBe('ISODate("1970-01-01T00:00:00.000Z")');
    expect(detectBson({ $numberDecimal: '9.99' })?.kind).toBe('decimal');
    expect(detectBson({ $numberLong: '42' })?.display).toBe('NumberLong(42)');
    expect(detectBson({ $numberInt: '7' })?.display).toBe('7');
    expect(detectBson({ $numberDouble: '1' })?.display).toBe('1.0');
    expect(detectBson({ $timestamp: { t: 1, i: 2 } })?.display).toBe('Timestamp(1, 2)');
    expect(detectBson({ $regularExpression: { pattern: 'ab', options: 'i' } })?.display).toBe('/ab/i');
  });

  it('renders UUID and generic binary', () => {
    const uuid = detectBson({ $binary: { base64: 'ASNFZ4mrze8BI0VniavN7w==', subType: '04' } });
    expect(uuid?.kind).toBe('uuid');
    expect(uuid?.display).toBe('UUID("01234567-89ab-cdef-0123-456789abcdef")');
    const bin = detectBson({ $binary: { base64: 'AAEC', subType: '00' } });
    expect(bin?.kind).toBe('binary');
    expect(bin?.detail).toContain('3 bytes');
  });

  it('ignores ordinary objects', () => {
    expect(detectBson({ $oid: 'x', other: 1 })).toBeNull();
    expect(detectBson({ a: 1 })).toBeNull();
    expect(detectBson('s')).toBeNull();
  });
});

describe('shellToExtJSON', () => {
  it('converts shell helpers', () => {
    expect(shellToExtJSON('{"_id": ObjectId("507f1f77bcf86cd799439011")}')).toBe('{"_id": {"$oid": "507f1f77bcf86cd799439011"}}');
    expect(shellToExtJSON("{d: ISODate('2024-01-01')}")).toBe('{"d": {"$date": "2024-01-01"}}');
    expect(shellToExtJSON('{n: NumberLong(5)}')).toBe('{"n": {"$numberLong": "5"}}');
    expect(shellToExtJSON('{d: new Date("2024-01-01")}')).toBe('{"d": {"$date": "2024-01-01"}}');
  });
  it('quotes bare keys and single-quoted strings', () => {
    const out = shellToExtJSON("{status: 'A', qty: {$lt: 30}, 'a.b': 1}");
    expect(JSON.parse(out)).toEqual({ status: 'A', qty: { $lt: 30 }, 'a.b': 1 });
  });
  it('leaves string contents alone', () => {
    expect(shellToExtJSON('{"s": "ObjectId(\\"x\\")"}')).toBe('{"s": "ObjectId(\\"x\\")"}');
  });
});

describe('normalizeInput', () => {
  it('validates shape', () => {
    expect(normalizeInput('', 'object')).toEqual({ value: '' });
    expect(normalizeInput('{"a":1}', 'object').error).toBeUndefined();
    expect(normalizeInput('[1]', 'object').error).toBeDefined();
    expect(normalizeInput('[{"$match":{}}]', 'array').error).toBeUndefined();
    expect(normalizeInput('{bad', 'object').error).toBeDefined();
  });
});

describe('formatting', () => {
  it('formats bytes and numbers', () => {
    expect(formatBytes(512)).toBe('512 B');
    expect(formatBytes(2048)).toBe('2.0 KiB');
    expect(num({ $numberLong: '12' })).toBe(12);
    expect(num(3)).toBe(3);
    expect(summarize([1, 2])).toBe('Array(2)');
  });
});
