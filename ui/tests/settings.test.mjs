import assert from 'node:assert/strict';
import test from 'node:test';
import vm from 'node:vm';
import { readFileSync } from 'node:fs';
const source = readFileSync(new URL('../settings.js', import.meta.url), 'utf8');
const settle = async () => { for (let i = 0; i < 40; i++)
    await Promise.resolve(); };
async function fixture({ platform = 'linux', scope = 'host', canWrite = true, deferred = false, readbackMismatch = false } = {}) {
    const descriptor = JSON.parse(readFileSync(new URL(`../../metadata/${platform}.json`, import.meta.url), 'utf8')).descriptor;
    let registration, revision = 7, values = {}, dirty = false, busy = false, timer = 0;
    const timers = new Map(), controls = [], writes = [], pending = [], controller = new AbortController();
    const element = () => ({ children: [], append(...items) { this.children.push(...items); }, replaceChildren(...items) { this.children = items; }, setAttribute() { } });
    const context = vm.createContext({ document: { createElement: element }, window: { AmaterasuExtensions: { v1: { register(id, page) { assert.equal(id, 'frame-limiter'); registration = page; } } } }, setTimeout(callback) { timers.set(++timer, callback); return timer; }, clearTimeout(id) { timers.delete(id); } });
    vm.runInContext(source, context);
    const make = (kind) => (options) => { let value = options.value; const control = { kind, options, element: element(), disposed: false, value: () => value, setValue(next) { value = next; }, dispose() { this.disposed = true; }, edit(next) { value = next; options.onChange(next); } }; controls.push(control); return control; };
    const sdk = { features: ['ui.settings/1'], signal: controller.signal, setDirty(value) { dirty = value; }, setBusy(value) { busy = value; },
        settings: { provider: 'amaterasu.frame-limiter', scope: { kind: scope }, canWrite, async describe() { return descriptor; }, async read() { return { revision, values: readbackMismatch && writes.length ? {} : structuredClone(values), effective: Object.fromEntries(descriptor.options.map(option => [option.id, { value: values[option.id] ?? option.definition.default, source: null }])) }; }, async update(expected, next) { assert.equal(expected, revision); writes.push({ expected, values: structuredClone(next) }); if (deferred)
                await new Promise(resolve => pending.push(resolve)); values = structuredClone(next); return { revision: ++revision }; } },
        ui: Object.fromEntries(['toggle', 'select', 'slider', 'numberField', 'textField', 'button'].map(kind => [kind, make(kind)])) };
    registration[scope === 'host' ? 'mountSettings' : 'mountApplication'](element(), sdk);
    await settle();
    return { controls, writes, pending, controller, dirty: () => dirty, busy: () => busy, async flush() { const callbacks = [...timers.values()]; timers.clear(); callbacks.forEach(callback => callback()); await settle(); } };
}
test('native descriptor selects platform controls and fractional FPS slider', async () => {
    for (const platform of ['linux', 'windows']) {
        const env = await fixture({ platform });
        const fps = env.controls.find(control => control.options.label === 'Frame rate limit (FPS)');
        assert.equal(fps.kind, 'slider');
        assert.equal(fps.options.minimum, 0);
        assert.equal(fps.options.maximum, 1000);
        fps.edit(59.94);
        await env.flush();
        assert.deepEqual(env.writes, [{ expected: 7, values: { frame_limiter_fps_limit: 59.94 } }]);
        assert.equal(env.dirty(), false);
        const provider = env.controls.find(control => control.options.label === 'Limiter');
        assert.equal(provider.options.choices.some(choice => choice.value === 'rtss'), platform === 'windows');
        env.controller.abort();
        assert.ok(env.controls.every(control => control.disposed));
    }
});
test('save readback preserves edits made during an in-flight write', async () => {
    const env = await fixture({ deferred: true, scope: 'application' }), fps = env.controls.find(control => control.options.label === 'Frame rate limit (FPS)');
    fps.edit(60);
    await env.flush();
    assert.equal(env.busy(), true);
    fps.edit(90);
    env.pending.shift()();
    await settle();
    assert.equal(env.dirty(), true);
    await env.flush();
    assert.equal(env.writes[1].expected, 8);
    env.pending.shift()();
    await settle();
    assert.equal(env.writes[1].values.frame_limiter_fps_limit, 90);
    assert.equal(env.dirty(), false);
});
test('unconfirmed readback keeps drafts and read-only accounts never write', async () => {
    const env = await fixture({ readbackMismatch: true });
    env.controls.find(control => control.options.label === 'Frame rate limit (FPS)').edit(60);
    await env.flush();
    assert.equal(env.dirty(), true);
    const readonly = await fixture({ canWrite: false });
    assert.ok(readonly.controls.every(control => control.options.disabled));
    readonly.controls.find(control => control.options.label === 'Frame rate limit (FPS)').edit(60);
    await readonly.flush();
    assert.equal(readonly.writes.length, 0);
});
