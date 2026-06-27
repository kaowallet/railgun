# RAILGUN Rust port — dev tasks.  Run `just` to list recipes.

manifest := "rust/Cargo.toml"
oracle   := "rust/oracle/gen.ts"
count    := "400"

# list available recipes
default:
    @just --list

# install the TS SDK's JS deps for the Bun oracle (one-time)
install:
    bun install

# build the whole Rust workspace
build:
    cargo build --manifest-path {{manifest}}

# all Rust tests (unit + fuzz replay against the current corpus)
test:
    cargo test --manifest-path {{manifest}}

# unit tests only (fast; skips the oracle-replay integration tests)
unit:
    cargo test --manifest-path {{manifest}} --lib

# regenerate the fuzz corpus from the TS oracle (random seed unless one is given)
gen seed="" count=count:
    #!/usr/bin/env bash
    set -euo pipefail
    SEED="{{seed}}"
    if [ -z "$SEED" ]; then SEED=$(( (RANDOM << 15) | RANDOM )); fi
    echo "oracle: seed=$SEED count={{count}}"
    NODE_ENV=test bun run {{oracle}} "$SEED" "{{count}}"

# replay the current corpus against Rust (no regeneration)
fuzz-check:
    cargo test --manifest-path {{manifest}} against_ts_oracle

# differential fuzz: fresh RANDOM-seed corpus from Bun, then replay against Rust
fuzz count=count:
    #!/usr/bin/env bash
    set -euo pipefail
    SEED=$(( (RANDOM << 15) | RANDOM ))
    echo "=== fuzz: seed=$SEED count={{count}} ==="
    NODE_ENV=test bun run {{oracle}} "$SEED" "{{count}}"
    if ! cargo test --manifest-path {{manifest}} against_ts_oracle; then
        echo "!! DIVERGENCE at seed=$SEED count={{count}}"
        echo "   reproduce: just gen $SEED {{count}} && just fuzz-check"
        exit 1
    fi

# run many fuzz rounds with fresh random seeds; stop on the first divergence
fuzz-sweep rounds="20" count="250":
    #!/usr/bin/env bash
    set -euo pipefail
    for i in $(seq 1 {{rounds}}); do
        SEED=$(( (RANDOM << 15) | RANDOM ))
        echo "=== round $i/{{rounds}}: seed=$SEED count={{count}} ==="
        NODE_ENV=test bun run {{oracle}} "$SEED" "{{count}}"
        if ! cargo test --manifest-path {{manifest}} --quiet against_ts_oracle; then
            echo "!! DIVERGENCE at seed=$SEED count={{count}}"
            echo "   reproduce: just gen $SEED {{count}} && just fuzz-check"
            exit 1
        fi
    done
    echo "all {{rounds}} rounds passed"

# restore the canonical committed corpus (fixed seed) before committing
gen-fixed:
    NODE_ENV=test bun run {{oracle}} 12648430 {{count}}

# remove build artifacts
clean:
    cargo clean --manifest-path {{manifest}}
