# Frame limiter service and policy

This crate owns frame-limiter settings, backend policy and effects. The default
Linux and Windows product compositions use the plugin's lifecycle callbacks
and the generic extension settings registry. Launch, RTSP and stream-session do not send
limiter-specific settings or call its apply/status/restore methods.

The `amaterasu.frame-limiter/1` service remains available inside the plugin for
legacy external callers. It is not granted to built-in streaming consumers.

The version 1 `apply` request carries the immutable effective settings for one
launch plus optional stream, Lossless Scaling, explicit client display-mode,
virtual-display, and frame-generation context. Missing or null context is
unknown; callers must not infer a client display override from
stream dimensions. Rate values are exact unsigned millihertz, and zero means
the known follow-stream/no-rate value. The selected registry resolves the
plugin's declared application/client fields before each prepared transition.
Other settings remain global. The legacy
`rtss_disable_vsync_ullm` input folds into `frame_limiter_disable_vsync`, and
callers persist only the canonical field. An empty RTSS install path selects
auto-detection.

## Runtime behavior

64-bit Windows reads RTSS profile values through `RTSSHooks64.dll`. The
lifecycle backend controls the `Profiles/Global` profile, including
desktop streams; the compatibility service can still target an executable
profile through its `.cfg` file. Before changing any bytes, the provider opens
that regular file without following a final-component reparse point, denies
write/delete sharing, and takes a nonblocking exclusive
Win32 byte-range lock over the full file range. It reads and compares the three
`[Framerate]` values while holding the lock, replaces only their numeric text,
flushes and verifies the file, then asks RTSS to reload the profile and checks
the values through the hooks API. An expected-value mismatch or lock failure
does not mutate the profile. A preexisting write-capable handle also makes the
transaction unavailable before mutation; it does not rely solely on byte-lock
enforcement. Apply and restore use the same transaction, with
the lease journal durable before apply and restore conditional on the exact
applied values.

The lock denies ordinary Windows reads and writes through other handles;
Windows documents that byte-range locks do not constrain memory-mapped file
writes.
The provider cannot coordinate with edits RTSS has already buffered in its UI,
or prevent a writer from changing the profile after the lock is released. The
post-reload readback catches changes visible at verification time. Later edits
remain intact because lease restore compares the current profile to the
applied snapshot and retains a stale lease instead of overwriting a mismatch.
If RTSS Hooks appears to show the original values already, restore still checks
the profile file under the lock; a third locked snapshot remains stale even if
the Hooks view is behind it.
The in-place file update is not crash-atomic; failed writes attempt to restore
the original bytes while the lock is held, and an unverified result leaves the
durable pending lease for recovery. Profiles with missing, duplicate, or
malformed frame-rate keys are refused. 32-bit Windows and non-Windows RTSS
requests remain unavailable. Auto tries the NVIDIA driver limiter only after
RTSS has confirmed that it owns no unresolved effect.

The global lifecycle lease records RTSS's limiter-disabled bit before applying
its profile. It enables the limiter only after the pending journal is durable,
preserves every unrelated flag, and restores the original bit after conditional
profile restoration. Known partial profile/flag transactions return to their
saved baseline during recovery; unrelated profile edits retain the lease for
recovery. Compatibility requests for an executable do not enable a globally
disabled limiter. The separate `frame_limiter_disable_vsync` option uses a
plugin-owned NVIDIA driver lease. If that required change fails without an
effect, the plugin restores its RTSS lease; an uncertain driver save retains
ownership for recovery. A missing Global profile is initialized with
unlimited default values only after its creation intent is durable. The provider
pins the Profiles directory, rejects reparse points, and creates the file
exclusively; a racing file is preserved. After cleanup the initialized default
profile remains. Failed initialization deletes only the newly created file
through its still-exclusive handle. Missing executable profiles on the legacy
service remain unavailable. A configured RTSS path may be absolute or relative
to a Windows Program Files directory. An empty path uses the running
installation, or the conventional installed directory during preparation.
An explicit path must match an already-running installation in the plugin's
Windows login session; it cannot redirect the Hooks API to a different copy.

Preparation can start a stopped RTSS installation. Status reads only inspect
an existing instance. Before loading or starting code, the plugin pins a
non-reparse installation beneath a system-resolved Program Files root, rejects
user-writable installation/code ACLs, verifies the executable and Hooks DLL
with Authenticode, and requires their signing certificates to match. Open code
handles prevent write/delete replacement, and the loaded DLL's file identity
must match the verified file. These checks use cached trust information without
network retrieval.

The plugin creates RTSS hidden and suspended, assigns it to a private
kill-on-close process job, then resumes it and waits for readiness. The owned
instance stays warm across stream transitions and pauses. Session cleanup
retires it only after all RTSS leases are gone, including when the final stream
cleanup arrives after session cleanup. An existing instance is never included
in that job. Failed startup and worker termination retire only the owned
process tree.

A lease belongs to the broker caller and `session_id`. An exact request retry
returns the same lease while RTSS still matches, and the retry check runs
before policy can return `not_needed` or `runtime_unavailable`. Changed
settings or target for that owner and session return `lease_conflict`, including
after restore while its tombstone is retained. Conflicts are scoped to one RTSS installation and profile. The lifecycle
backend serializes the shared global target; compatibility callers can own
independent executable profiles. A stale lease continues to reserve its profile until
it is restored or resolved. `status` lists only that caller's leases and may
filter by session. When no owned lease exists, `status` probes the RTSS process
and required API and reports provider availability separately from lease state.

The provider-independent lease manager supports exact restore and retains a
lease after restore failure. A detected external change is reported as
`stale_lease` and is never overwritten. A precondition mismatch between the
lease manager's read and the locked file transaction is also rechecked; if the
profile is not already at its original snapshot, the lease remains stale.
Legacy leases from a runtime that created a profile remain stale; recovery never
deletes or overwrites that profile. The journal keeps the latest 256 completed
lease tombstones; a repeated restore returns `restored` while its tombstone
remains, then returns `not_found` after eviction. Callers should use unique
session IDs.

The lease journal is stored under the current user's `LOCALAPPDATA` (falling
back to `APPDATA`) in `Amaterasu/frame-limiter/leases.json`. The runtime API's
state-root grant is restricted to the state module. Before an RTSS mutation,
the module atomically persists a pending lease with its exact before and
intended values. On startup, a provider with safe mutation support reconciles
that record with its provider: an exact applied state becomes active, an exact
before-state is finalized as no effect, and a third state remains stale for
owner-visible recovery. If write capability is unavailable, an unverified
pending effect remains stale even when current values happen to match the
intent. Older journal records for lease-created profiles are kept stale rather
than automatically deleting or overwriting the profile. A readback mismatch is
rolled back only when the current profile and global limiter flag still match
the attempted change.

Windows native effects execute in a separate process launched by the plugin
from its already selected DLL. The plugin uses the system `rundll32.exe` and a
private pipe; the host does not interpret the worker protocol or package an
additional helper. The child belongs to a kill-on-close job and all parent I/O
uses bounded pipe polling without module-owned bridge threads. This is a fault-isolation
boundary for trusted native code, not a permission sandbox.

Host shutdown records the earliest announced deadline and closes new legacy
apply admission. Declared lifecycle consumers keep their policy and can finish
callbacks before dependency-ordered provider quiescence. Quiescence closes the
worker input, continues bounded polling, and reports ready only after actual
worker exit and verified policy retirement. Windows additionally requires the
child's restoration acknowledgement and an empty owned process job. Linux
requires successful EOF cleanup and absence of the temporary policy file before
durably retiring receipts. A kill request, an expired budget, or an unknown
cleanup target never establishes cleanup. Failed persistence retains the exact
retirement proof for retry without creating another worker or renewing time.

Lifecycle and compatibility requests remain asynchronous in the host process.
The parent limits the queue to 32 requests and retains 256 completed receipts.
Worker startup has a five-second deadline. RTSS preparation has a four-second
watchdog; other in-flight native stages have a one-second watchdog. All remain
bounded by the caller's overall deadline. On a stall the parent first
terminates the owned process tree and confirms that no descendant remains.
Auto and explicit RTSS selection may retry through NVIDIA
only when both durable journals prove there is no outstanding native effect.
Unrecognized state, an outstanding lease, an expired request or a stalled
NVIDIA call returns recovery-required rather than attempting another backend.

## Policy behavior

On 64-bit Windows the NVIDIA backend uses the system NVAPI DRS interface. It
records the selected profile's name, setting values and override provenance
before saving changes. Explicit NVIDIA selection bypasses RTSS. Auto may fall
back after a confirmed RTSS failure; pending native ownership prevents fallback.
When RTSS is active, the plugin also disables an available NVIDIA driver cap so
the two limiters do not compete. Requested VSync control can operate without a
frame cap. Smooth Motion requests enable its driver flag and API mask only on
driver 571.86 or newer. Driver limits round to whole FPS and clamp to 1–1023.

The separate `nvcp-leases.json` journal is locked, bounded, and written before
driver saves. Cleanup compares only the settings that lease owns; explicit
values are restored, and formerly inherited settings have the temporary
override removed. Uncertain or interrupted saves are reconciled against the
recorded before/after states. An unrelated value keeps the lease unresolved.
NVAPI does not expose an atomic compare-and-save operation across independent
applications; a writer racing between the snapshot check and driver save
remains a runtime qualification limit.

The Windows RTSS policy changes the configured sync type only for an active
frame-generation policy with Auto or RTSS selected. Smooth Motion uses Front
Edge Sync. Automatic virtual-display policy selects Reflex only when enabled,
the global override is off, and NVIDIA is present without an AMD adapter.
Active game-provided frame generation selects Reflex on supported NVIDIA
hardware even when the virtual-display automatic mode or global override is
off; an explicit application/client RTSS type takes priority. A zero configured
FPS limit uses, in order, a Lossless Scaling limit, explicit client display-mode
rate, and authoritative requested-stream FPS. When those sources are known to
be absent or zero, the result remains `FollowStream`.

An explicit active `lossless-scaling` frame-generation mode also activates the
limiter policy even when no Lossless Scaling FPS limit is supplied. Its RTSS
sync type follows the generic frame-generation policy, which uses Front Edge
Sync unless virtual-display policy selects Reflex.

When the effective rate source is Lossless Scaling, the RTSS profile value is
derived from half the target rate and rounded to the nearest whole FPS, with
half-FPS ties rounded upward. This matches the reference's game-input cap for
generated output. An explicit configured frame-limiter rate keeps precedence
and is written exactly; all other rate sources also keep their exact
millihertz ratio. The policy plan continues to report the resolved LS output
target, while the RTSS lease records the derived game-input cap. Native RTSS
apply and restore use the conditional profile transaction described above;
live RTSS behavior still needs Windows qualification.

## Remaining integration and platform gates

The plugin contains an extension-registry settings descriptor and a typed
settings validator for the independently approved `nonary.frame-limiter/1`
service. Set
`extension_registry_principal` to the operator-selected registry identity and
approve that method before registering it. The default Linux session profile
selects this extension with limiting disabled and exposes the plugin-owned
options through the generic extension settings editor. The Windows product
selects the same contracts with its Windows descriptor; its lifecycle journal uses
the worker state root through an explicit context grant. The legacy product
and application/device editors no longer define or validate limiter fields. Their storage readers
retain options they do not own as bounded opaque data, and unrelated edits
preserve those values, including false, zero and null. The plugin still needs
an explicit import of older saved limiter settings into its registry scopes;
retention alone does not activate those settings. The
descriptor for a target platform can be generated with
`cargo run -p amaterasu-frame-limiter --example print_settings_descriptor -- linux`
(or `windows` / `macos`).

An explicitly configured `lifecycle_coordinator` (`principal` and `service`)
also registers generic v1 lifecycle methods. The participant asynchronously reads
the exact authorized context before responding. Linux callbacks declare a
plugin-owned mutation domain, validate the admitted plan, and return bounded
receipts while the worker installs hooks and applies or removes a policy.
Status queries recover the recorded outcome without replaying effects. Exact
cleanup generations prevent a delayed stream release from removing a resumed
stream's policy. An uncertain worker effect retires the worker and fences further
effects until recovery settles; it is never reported as successful preparation
or cleanup merely because the worker was stopped.
The default Linux profile uses external capture ownership: lifecycle callbacks
run before application launch and stream start, but capture and input stay with
their selected existing providers. No capture candidate is supplied by the
limiter. RTSP and stream-session reject a change of ownership mode mid-session.
Explicit display-composition packaging uses `--external-extension-composition`
to supply its own reviewed lifecycle graph; that graph currently excludes this
default participant rather than mixing unsupported v1/v2 participants.

The Linux plugin also contains a bundled Proton helper, bounded discovery,
temporary policy store, and subprocess bridge. Fixture tests exercise the
installer and launch-time environment edits. A native integration test loads the
independently built module through its ABI and drives the real broker and
lifecycle coordinator through session preparation and cleanup in a disposable
Proton installation. The plugin's policy projection uses a configured limit first, then a Lossless Scaling
output target (or its requested stream rate), then an explicit client mode, then
the requested stream rate; absent client context
is not treated as proof that no override exists. The installer serializes its
own writes and checks the existing file
before atomic replacement; an unrelated writer that ignores the lock can still
race the final comparison. No live Proton installation has been modified or
qualified by these tests. The worker normally uses `XDG_RUNTIME_DIR` and the
current user's Steam roots. Trusted plugin startup settings may instead supply
`proton_runtime_directory` and `proton_steam_roots`; paths must be absolute and
the worker still checks ownership before writing.

The lifecycle journal is persistent: it lives under
`$XDG_STATE_HOME/amaterasu/frame-limiter`, falling back to
`$HOME/.local/state/amaterasu/frame-limiter`. It retains provider revisions,
receipts and cleanup ownership across logout and reboot. On first use, the
provider imports an existing runtime journal while holding both journal locks;
an existing persistent journal always takes precedence. Worker sockets and
temporary policies remain under the runtime directory. Trusted startup settings
may override journal storage with the absolute `proton_state_directory` path.

When Steam's pressure-vessel runtime hides that directory, the Proton hook
reads its policy from the live plugin worker over a bounded Unix abstract
socket. Both ends check the peer's user ID; the socket is specific to that
runtime root and disappears with the worker. The worker checks its owned state
before answering and returns only the selected application's policy.
Inside the container, the hook supplies private Vulkan manifests pointing to
the installed host MangoHUD libraries and architecture-specific preload links.
Those files are removed when Proton exits. Existing overlay configuration and
other Vulkan layers are retained. Installer upgrades replace only an exact
recognized previous helper; externally changed helpers remain untouched.

The Linux plugin keeps `lifecycle.json` beside its temporary `active.json`
policy. Its private journal records a stable random owner ID, receipt identities,
target generations, and the exact before/after policy intent before submitting
an effect. A process lock permits one module owner; directory-relative file
operations reject symlinks and shared writable state, compare file identity
before replacement, and sync the new journal and containing directory.
The journal is bounded to 4 MiB, 32 pending receipts and 256 completed receipts.

On a worker exit or module restart, a replacement worker first removes only an
inactive policy with that journal's owner ID and a matching before/after policy
snapshot. Other owners, changed policies and unrecognized legacy files remain
untouched and keep recovery blocked. Readiness means the previous policy is
absent; it never reactivates saved settings. The plugin then retires the saved
generations, confirms cleanup receipts, and reports old preparations as requiring
recovery. Queued effects from the old worker are retired instead of replayed.
New streams can prepare after this reconciliation, while delayed cleanup retains
its original target identity. The native broker test restarts the loaded plugin
between preparation and cleanup for each Linux backend.

Run the native integration check after building the module:

```sh
cargo build -p amaterasu-frame-limiter
AMATERASU_FRAME_LIMITER_LIBRARY="$PWD/target/debug/libamaterasu_frame_limiter.so" \
  cargo test -p amaterasu-session-lifecycle --test frame_limiter -- --ignored
```

The test creates its own subprocess and private directories. It does not alter
the installed Proton tools or the current user's settings.

The lifecycle contract is implemented behind the fake-provider test seam.
Live RTSS process/API detection, profile locking, reload, and game behavior were
not exercised because RTSS is not installed and running in the build
environment. RTSS hooks may also be blocked by a game's anti-cheat. The
community `SyncLimiter` numeric mapping and read behavior still require
verification against supported RTSS versions.
The Windows branch is cross-checked for `x86_64-pc-windows-gnu`, including its
test targets. Its unit tests also run in a private Wine prefix, including the
native create-new, write-sharing and conditional file-update checks. This does
not qualify RTSS Hooks or game behavior on Windows. The file transaction denies
competing write handles in addition to the byte-range lock; it does not depend
on Wine enforcing the Windows byte-lock behavior.
RTSS process warm-up, owned-tree retirement, read-only probes and watchdog
fallback are covered by process and provider fixtures. Those fixtures also
verify that an independently launched process survives owned-tree cleanup.
Path confinement, mutable-code rejection and unsigned-code rejection run in
the private Wine prefix; a real signed RTSS installation still needs Windows
qualification. The actual DLL entrypoint is exercised in a private
Wine process with disposable journals, including paths with spaces and commas.
The NVIDIA backend and VSync control are implemented and tested through a DRS
ABI fixture; live driver persistence and game behavior still need Windows
qualification. The reference's special repair of preexisting Smooth Motion
Off overrides is not yet implemented. The new Linux
lifecycle backend supports Proton launch hooks, including MangoHUD limiting or
overlay settings. Native launches receive the same plugin-owned limits through
the generic `amaterasu.launch-environment` constraint. The launch consumer merges
inherited configuration and rejects conflicts before spawning. The plugin's
descriptor advertises that capability; startup composition must grant it explicitly.
Configured frame-generation mode and Lossless Scaling context are resolved inside
the plugin from application/client properties. Automatic virtual-display/GPU
discovery and scoped RTSS-type provenance remain unfinished. MangoHUD executable
discovery stays inside the plugin; Auto and combined mode use Proton without
the overlay when it is absent. Explicit MangoHUD selection reports unavailable.
Trusted startup can set bounded absolute `mangohud_search_paths` instead of PATH.
Safe upgrades from older installer compositions and ownership-free legacy
runtime policy files remain incomplete.
Application and paired-client overrides are edited through the generic plugin
settings dialogs and frozen by the registry for each prepared transition.
The legacy `/1` lease service still reports Linux providers as
unavailable; Linux lifecycle effects use the separately approved plugin service.

Migration of unfinished legacy stream-owned effects remains a release gate.
Stream-session reads old inactive journal markers without writing them again;
an old journal declaring a pending effect is preserved and blocks new sessions.
It cannot be treated as clean just because the old direct RPC path was removed.

Focused policy, lifecycle, and disposable profile-file transaction tests are in
`src/tests.rs`, `src/lease.rs`, and `src/rtss_profile.rs`; strict service wire
tests are inline in `src/service.rs`.

## Independent core module and UI

This module is developed in its own public repository and selected as a core
component through Amaterasu's trusted startup composition. Native service IDs,
state documents and cleanup journals are preserved by the extraction. A source
repository or a UI bundle is not an installed or activated package.

Build against an explicit public SDK checkout, keeping artifacts on your build
volume:

```sh
CARGO_TARGET_DIR=/path/to/build python3 scripts/build-native.py /path/to/amaterasu --test
CARGO_TARGET_DIR=/path/to/build python3 scripts/build-native.py /path/to/amaterasu --clippy
```

The separately signed browser UI lives in `ui/`. It uses only the public browser
SDK and approved versioned methods. It supplies host settings and an application
editor section. Saving settings does not interrupt an active stream. Run UI
regressions with `node --test ui/tests/*.test.mjs`.

Prepare a signed UI bundle with:

```text
scripts/package-ui.sh WEB_EXTENSION_TOOL OUTPUT SEQUENCE EXPIRES_UNIX SECRET_HEX_FILE
```

This prepares assets and signatures; it does not install, select, restart or
activate anything. Native and browser qualification are separate from installed
host and real-client qualification. Windows hardware testing remains deferred.

The registry-backed UI binds `amaterasu.frame-limiter` through `ui.settings/1`.
The selected native descriptor supplies platform choices, option bounds and
scopes, including fractional FPS. The UI serializes debounced writes, confirms
readback, retains edits made during saving and retires its controls on close.
Existing RTSS/NVIDIA/MangoHUD/Proton lease policy and cleanup remain unchanged.

The native implementation was extracted from Amaterasu at
`524e578c9d2b1c695b11ab35830510295519e909`; its earlier source history remains in
[the Amaterasu repository](https://github.com/nonary-streams/amaterasu).
Use the published `codex/core-module-plugins` SDK branch or a later compatible
checkout for the new UI and operation contracts.
