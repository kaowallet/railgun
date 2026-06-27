# RAILGUN Rust port — differential fuzzing.
#
# `just` runs the WHOLE thing: it builds the Rust workspace once, then in
# parallel (a) replays the port against several independent Bun-oracle corpora,
# each generated from a fresh RANDOM seed, and (b) runs the unit tests. A
# divergence in any round prints the exact command to reproduce it.
#
# Arguments are positional — `just fuzz [jobs] [count] [seed]`:
#   just                   # 8 parallel rounds × 400 cases, random seeds
#   just fuzz 16 1000      # a heavier sweep
#   just fuzz 8 400 42     # reproducible — jobs use seeds 42, 43, 44, …
#
# Refresh the committed corpus (used by a plain `cargo test`, no Bun needed):
#   NODE_ENV=test bun run rust/oracle/gen.ts 12648430 400

manifest := justfile_directory() / "rust/Cargo.toml"
oracle   := justfile_directory() / "rust/oracle/gen.ts"
corpora  := justfile_directory() / "rust/target/fuzz-corpora"

# Build once, then fuzz everything in parallel against fresh random-seed corpora.
fuzz jobs="8" count="400" seed="":
    #!/usr/bin/env bash
    set -uo pipefail
    cd "{{justfile_directory()}}"

    jobs="{{jobs}}"; count="{{count}}"; seed="{{seed}}"
    [[ "$jobs"  =~ ^[1-9][0-9]*$ ]] || { echo "jobs must be a positive integer (got '$jobs'); usage: just fuzz [jobs] [count] [seed]"; exit 2; }
    [[ "$count" =~ ^[1-9][0-9]*$ ]] || { echo "count must be a positive integer (got '$count')"; exit 2; }
    [[ -z "$seed" || "$seed" =~ ^[0-9]+$ ]] || { echo "seed must be a non-negative integer (got '$seed')"; exit 2; }

    # One-time: the Bun oracle needs the TS SDK's JS deps installed.
    [ -d node_modules ] || bun install

    rm -rf "{{corpora}}"; mkdir -p "{{corpora}}"

    echo "▸ building test binaries + generating $jobs corpora (parallel)…"
    cargo test --manifest-path "{{manifest}}" --no-run --quiet &
    build=$!

    declare -a seeds
    gens=()
    for i in $(seq 1 "$jobs"); do
        if [ -n "$seed" ]; then
            s=$(( seed + i - 1 ))
        else
            s=$(( ((RANDOM << 15) ^ (RANDOM << 2) ^ RANDOM) & 0x7fffffff ))
        fi
        seeds[i]=$s
        ( VECTORS_DIR="{{corpora}}/$i" NODE_ENV=test bun run "{{oracle}}" "$s" "$count" \
            >"{{corpora}}/$i.gen.log" 2>&1 ) &
        gens+=($!)
    done

    wait "$build" || { echo "✗ build failed"; exit 1; }
    genfail=0
    for p in "${gens[@]}"; do wait "$p" || genfail=1; done
    [ $genfail -eq 0 ] || { echo "✗ corpus generation failed — see {{corpora}}/*.gen.log"; exit 1; }

    echo "▸ replaying ${#gens[@]} corpora + unit tests (parallel)…"
    ( cargo test --manifest-path "{{manifest}}" --lib --quiet >"{{corpora}}/unit.log" 2>&1 ) &
    unit=$!

    reps=(); idxs=()
    for i in $(seq 1 "$jobs"); do
        ( RAILGUN_VECTORS_DIR="{{corpora}}/$i" cargo test --manifest-path "{{manifest}}" \
            --quiet against_ts_oracle >"{{corpora}}/$i.test.log" 2>&1 ) &
        reps+=($!); idxs+=($i)
    done

    status=0
    if ! wait "$unit"; then echo "✗ unit tests FAILED:"; cat "{{corpora}}/unit.log"; status=1; fi
    for k in "${!reps[@]}"; do
        i=${idxs[$k]}
        if ! wait "${reps[$k]}"; then
            echo "✗ DIVERGENCE — seed ${seeds[$i]} (corpus $i):"
            cat "{{corpora}}/$i.test.log"
            echo "  reproduce: VECTORS_DIR={{corpora}}/$i bun run {{oracle}} ${seeds[$i]} $count && RAILGUN_VECTORS_DIR={{corpora}}/$i cargo test --manifest-path {{manifest}} against_ts_oracle"
            status=1
        fi
    done

    if [ $status -eq 0 ]; then
        echo "✓ all green — unit tests + $jobs random-seed fuzz rounds × $count cases each"
        echo "  seeds: ${seeds[*]}"
    fi
    exit $status
