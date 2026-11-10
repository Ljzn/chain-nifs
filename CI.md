# Validation and CI scope

Local validation is Apple M2 arm64,8GiB, OTP27,Elixir1.20.5,Rust1.96.0,release NIF. GitHub Actions configuration is included for Ubuntu24.04 x86-64 with fixed action commits, OTP27.3.4.19, Elixir1.20.5 and Node22. It has not been run remotely: this project is local and has not been published to GitHub.

Configured checks: locked submodule,local tools, mix/cargo formatting,Clippyalltargets -Dwarnings,Rust unit tests,release NIF compile,actual ExUnit suite,independent official TypeScript oracle regeneration,randomized signature/full-payment crossverification,normal reload andHex/RustSec audits. No advisory ignores. cargo-audit0.22.2 is pinned because0.21.2 cannot parse current CVSS4.0 advisories.

Real local RustSec scan used cargo-audit0.22.2 from the previous standalone prototype, against this project's actual nativeCargo.lock and existing advisory DB d9cb059f3217db87aeccd190b81eaffe8cc29cb9(1430advisories),--no-fetch. It scanned59crates with exit0 and no reported advisories. Hex audit returned no retired/security advisory packages; exact oracle npm lock audit also returned0 vulnerabilities (results/npm-audit.json). This is dated database evidence, not a complete security audit; the cargo-audit executable itself is not part of the new project's runtime/build dependency. Builds do not depend on adjacent projects.

The oracle contains2seededkeypairs,4explicitrndsignatures,1walletHKDFcase,6addresses and3network2in2outpayments. Corecapture signatures and NISTACVPsubset additionally verified. Regeneration uses unmodified official TypeScript modules with source hashes; native signing is independently verified by these modules. This is stronger than same-library self-check, but does not replace node testmempoolaccept/regtest admission.

The64input test is full construction/sign/selfverify/serialize/parse/verify with all supplied input amounts. Mutation/bounds regressions are deterministic and finite; no coverage-guided fuzz/long-running soak claim. Concurrency is bounded to8testcallers using32independent keys; no sustained service-throughput claim.

Normal unload/reload demonstrates no retained worker threads on ordinary completion. It does not demonstrate recovery frompanic, nativeabort, allocatorOOM, or memorycorruption. No production panic injection NIF is exposed.
