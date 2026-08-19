# Sparrow suitability and upstream strategy

## Decision

Sparrow is a good build, JavaFX, packaging, and regression scaffold for
Qparrow. Its Bitcoin wallet domain model is not a BTQ protocol library and is
not used for custody.

| Area | Decision |
|---|---|
| JavaFX/application lifecycle | Reuse the scaffold |
| Gradle/JLink dependencies | Minimal independent `qparrow-app` subproject |
| Inherited regression tests | Keep as upstream merge tripwires |
| Drongo Bitcoin keys, transactions, and PSBT | Never pass BTQ custody data |
| Electrum, HWI, terminal wallet | Do not initialize |
| BTQ derivation/signing/state | New isolated `btq.custody` implementation |

The active seam is:

```text
QparrowLauncher → QparrowDesktop → BtqCustodyWallet
                                  ├─ local vault/state/ML-DSA/PSBT
                                  └─ BtqWatchOnlyCore → BTQ Core RPC
```

Sparrow's central launcher, controllers, resources, and services remain
byte-for-byte upstream. The distributable is the independent `qparrow-app`
module, which compiles only the Qparrow launcher/UI and BTQ packages with
JavaFX, Gson, Bouncy Castle, JCommander, and SLF4J. The fork owns four edits to
upstream-maintained files so the same custody sources compile in Sparrow's
complete regression suite: the `include 'qparrow-app'` line in
`settings.gradle`, the `apply from: 'qparrow.gradle'` hook at the end of
`build.gradle`, `requires org.bouncycastle.provider` in
`src/main/java/module-info.java`, and the Qparrow content of `README.md`.
Protocol code is additive under `com.sparrowwallet.sparrow.btq`.

There is intentionally no backward compatibility. `BtqCoreWallet`, the former
node-key path, and its `createp2mrspend`/`signp2mrtransaction` tests were
deleted. Qparrow cannot open Sparrow wallets, Core private-key wallets, or
earlier Qparrow prototypes.

## License

Sparrow's Apache License 2.0 permits modification and redistribution, including
commercial derivative distribution, subject to preservation of the license,
notices, and attribution. Qparrow retains upstream headers and provides NOTICE.
The license grants no trademark rights; Qparrow uses its own name, package
image, launcher, release identity, and support channel.

BTQ Core is a separate MIT-licensed process reached through JSON-RPC; it is not
copied or linked into Qparrow. Final release branding and binary notices should
still receive legal review.

## Upstream update procedure

1. Merge/rebase the desired Sparrow release without editing BTQ protocol code.
2. Re-check every upstream-maintained file the fork edits, in full — a Sparrow
   release that rewrites one of these hunks silently drops the fork's edit:
   - `settings.gradle` — `include 'qparrow-app'`;
   - `build.gradle` — `apply from: 'qparrow.gradle'` at end of file;
   - `src/main/java/module-info.java` — `requires org.bouncycastle.provider`
     (losing this breaks the root compile);
   - `README.md` — the Qparrow description replacing Sparrow's.
3. Compile and run the full inherited suite.
4. Run all BTQ custody tests and the real exact-Core regtest gate.
5. Compare BTQ Core consensus/policy/PSBT changes with
   `docs/BTQ_WALLET_REFERENCE_MAP.md` before accepting the update.
6. Build `:qparrow-app:jpackageImage` and verify the minimal module graph
   (`verifyQparrowIsolation`), the Qparrow bundle identifier, the legal
   inventory, and that `Qparrow.cfg` still carries
   `-XX:-HeapDumpOnOutOfMemoryError`. The packaged Qparrow app
   (`qparrow-app/build.gradle`) runs with that flag; the root Sparrow build
   enables heap dumps and also compiles the custody sources, so only the Qparrow
   app image carries this hardening.
