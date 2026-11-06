// Plugin-owned controls; native metadata supplies platform choices and bounds.
(() => {
    const mount = (container, sdk) => {
        if (!sdk.features?.includes('ui.settings/1') || sdk.settings?.provider !== 'amaterasu.frame-limiter' || !sdk.settings.describe)
            throw new Error('Frame limiting requires scoped settings SDK support.');
        const settings = sdk.settings;
        const fields = document.createElement('div');
        const status = document.createElement('p');
        status.setAttribute('role', 'status');
        const help = document.createElement('p');
        help.textContent = 'Choose how games are paced during streaming. Saved changes apply to a new application session; an active limiter lease keeps its current policy.';
        const controls = new Map();
        const same = (a, b) => JSON.stringify(Object.entries(a).sort()) === JSON.stringify(Object.entries(b).sort());
        let state, descriptor, draft = {}, baseline = {}, generation = 0, saving = false, timer, disposed = false;
        const dirty = () => !same(draft, baseline);
        const updateDraftState = () => sdk.setDirty(dirty());
        const cancelTimer = () => { clearTimeout(timer); timer = undefined; };
        const schedule = () => { cancelTimer(); if (!disposed && dirty())
            timer = setTimeout(() => { void save(); }, 250); };
        const changed = (id, value, inherit) => {
            if (!settings.canWrite || disposed)
                return;
            if (inherit)
                delete draft[id];
            else
                draft[id] = value;
            generation++;
            updateDraftState();
            status.textContent = dirty() ? 'Changes waiting to save…' : 'No unsaved changes.';
            schedule();
        };
        const check = value => {
            if (!value || !Number.isSafeInteger(value.revision) || value.revision < 0 ||
                !value.values || typeof value.values !== 'object' || Array.isArray(value.values) ||
                !value.effective || typeof value.effective !== 'object')
                throw new Error('Invalid frame limiting settings.');
            return value;
        };
        const reflect = () => {
            for (const [id, item] of controls) {
                const inherited = !Object.hasOwn(draft, id);
                item.inherit?.setValue(inherited);
                item.control.setValue(inherited ? state.effective[id].value : draft[id]);
            }
        };
        async function save() {
            cancelTimer();
            if (saving || disposed || !state || !dirty() || !settings.canWrite)
                return;
            saving = true;
            sdk.setBusy(true);
            const submitted = { ...draft }, submittedGeneration = generation;
            status.textContent = 'Saving frame limiting settings…';
            let confirmed = false;
            try {
                const result = await settings.update(state.revision, submitted);
                if (disposed)
                    return;
                if (!Number.isSafeInteger(result.revision) || result.revision <= state.revision)
                    throw new Error('Save revision was not confirmed. Reload before retrying.');
                const refreshed = check(await settings.read());
                if (disposed)
                    return;
                if (refreshed.revision !== result.revision || !same(refreshed.values, submitted))
                    throw new Error('Saved values could not be confirmed. Reload before retrying.');
                state = refreshed;
                baseline = submitted;
                confirmed = true;
                if (generation === submittedGeneration)
                    reflect();
                updateDraftState();
                status.textContent = 'Frame limiting settings saved for the next application session.';
            }
            catch (error) {
                if (!disposed) {
                    status.textContent = `Unable to confirm frame limiting settings: ${error.message}`;
                    sdk.setDirty(true);
                }
            }
            finally {
                saving = false;
                if (!disposed) {
                    sdk.setBusy(false);
                    if (confirmed && generation !== submittedGeneration)
                        schedule();
                }
            }
        }
        const saveButton = sdk.ui.button({ label: 'Save frame limiting settings', disabled: !settings.canWrite, onClick: save });
        container.replaceChildren(help, fields, saveButton.element, status);
        status.textContent = 'Loading frame limiting settings…';
        void Promise.all([settings.describe(), settings.read()]).then(([metadata, settingsDocument]) => {
            if (disposed)
                return;
            if (metadata.provider !== settings.provider || !Array.isArray(metadata.options) || metadata.options.length > 128)
                throw new Error('Invalid frame limiting descriptor.');
            descriptor = metadata;
            state = check(settingsDocument);
            draft = { ...state.values };
            baseline = { ...draft };
            const scope = settings.scope.kind;
            for (const option of descriptor.options.filter(option => option.allowed_scopes.includes(scope))) {
                const id = option.id, definition = option.definition;
                if (controls.has(id) || !Object.hasOwn(state.effective, id))
                    throw new Error('Invalid frame limiting field.');
                const value = Object.hasOwn(draft, id) ? draft[id] : state.effective[id].value;
                const options = { label: option.label, help: option.help, value, disabled: !settings.canWrite, onChange(value) {
                        controls.get(id).inherit?.setValue(false);
                        changed(id, value, false);
                    } };
                let control;
                if (definition.type === 'boolean')
                    control = sdk.ui.toggle(options);
                else if (definition.type === 'enum')
                    control = sdk.ui.select({ ...options, choices: definition.options.map(value => ({ value, label: option.choice_labels?.[value] ?? value })) });
                else if (['integer', 'decimal'].includes(definition.type)) {
                    const bounds = { minimum: definition.minimum, maximum: definition.maximum, step: definition.type === 'integer' ? 1 : 0.01 };
                    control = option.presentation === 'slider' ? sdk.ui.slider({ ...options, ...bounds }) : sdk.ui.numberField({ ...options, ...bounds });
                }
                else if (definition.type === 'string')
                    control = sdk.ui.textField({ ...options, maxLength: definition.max_length });
                else
                    throw new Error(`Unsupported frame limiting setting ${id}.`);
                const inherit = scope === 'host' ? null : sdk.ui.toggle({ label: `Use inherited ${option.label.toLowerCase()}`,
                    value: !Object.hasOwn(draft, id), disabled: !settings.canWrite, onChange(value) {
                        changed(id, control.value(), value);
                        if (value)
                            control.setValue(state.effective[id].value);
                    } });
                const row = document.createElement('div');
                row.className = 'frame-limiter-setting';
                row.append(control.element);
                if (inherit)
                    row.append(inherit.element);
                fields.append(row);
                controls.set(id, { control, inherit });
            }
            updateDraftState();
            status.textContent = settings.canWrite ? 'Frame limiting settings are up to date.' : 'Frame limiting settings are read-only.';
        }).catch(error => { if (!disposed)
            status.textContent = `Unable to load frame limiting settings: ${error.message}`; });
        const dispose = () => { if (disposed)
            return; disposed = true; cancelTimer(); for (const item of controls.values()) {
            item.control.dispose();
            item.inherit?.dispose();
        } controls.clear(); saveButton.dispose(); };
        sdk.signal.addEventListener('abort', dispose, { once: true });
        return dispose;
    };
    window.AmaterasuExtensions.v1.register('frame-limiter', { title: 'Frame limiting', mountSettings: mount, mountApplication: mount });
})();
