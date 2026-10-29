#!/usr/bin/env bash
#
# mayhem/build.sh — build this repo's fuzz harness(es). EDIT per repo.
#
# Runs inside the commit image (mayhem/Dockerfile) as `mayhem` in /mayhem. The base image
# (ghcr.io/savantenvs/base) already exports the build contract — use these, don't redefine:
#   CC, CXX             stock clang / clang++
#   LIB_FUZZING_ENGINE  -fsanitize=fuzzer   (link into each harness that has a LLVMFuzzer entry)
#   SANITIZER_FLAGS     -fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer
#                       (ASan + UBSan, both set to HALT — so Mayhem catches memory AND UB defects)
#   DEBUG_FLAGS         -g -gdwarf-3   (DWARF debug info — always on for fuzz/standalone builds,
#                       independent of the sanitizer off-switch; DWARF version must be < 4)
#   RUST_DEBUG_FLAGS    -C debuginfo=2 -C force-frame-pointers=yes -C llvm-args=-gdwarf-3
#                       (thread through RUSTFLAGS on every cargo-fuzz build)
#   GO_DEBUG_FLAGS      -gcflags=all=-N -l
#                       (thread through go build / go-fuzz-build so the linked ELF keeps symbols)
#   SRC                 /mayhem (the repo source)
#
# Contract: build EVERYTHING here — one runnable binary per fuzz harness, AND the project's test
# suite (so mayhem/test.sh only has to RUN it, never compile). Keep it ADDITIVE (build upstream as
# upstream documents; don't edit upstream files). IMPORTANT: build the PROJECT ITSELF with
# $SANITIZER_FLAGS and $DEBUG_FLAGS (not just the harness) so the fuzzed code is instrumented
# AND carries DWARF < 4 symbols — otherwise ASan/UBSan only see the harness, not the library
# you're trying to find bugs in, and backtraces won't resolve project source lines. Build the TEST
# suite with the project's NORMAL flags (a clean, independent build) so test.sh stays an honest
# functional oracle and won't false-fail on benign UB. Leave the test binary/runner where test.sh
# expects it.
set -euo pipefail

# clang rejects SOURCE_DATE_EPOCH='' (empty) — it must be unset or a valid integer.
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

# Build knobs come from the ENVIRONMENT (overridable), with sane defaults — no if-statements,
# just parameter-expansion fallbacks. Default sanitizers are the base's ASan+UBSan (halting); override
# per build via the Dockerfile's `--build-arg SANITIZER_FLAGS="..."`.
# NB: SANITIZER_FLAGS uses `=` (no colon) on purpose — `=` only fills when the var is UNSET, so an
# explicit EMPTY value (`--build-arg SANITIZER_FLAGS=`) is honored and builds with NO sanitizers
# (useful when you want the program's natural crash / full backtrace, not an ASan report). The other
# knobs use `:=` (default on empty too). MAYHEM_JOBS sets build parallelism (falls back to nproc).
: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
# DEBUG_FLAGS carries DWARF debug info INDEPENDENTLY of the sanitizer off-switch (so an empty
# SANITIZER_FLAGS still yields DWARF symbols). DWARF MUST be < 4 (Mayhem triage can't read >=4); clang-19's
# plain `-g` emits DWARF-5, so `-gdwarf-3` is explicit. Apply $DEBUG_FLAGS to the fuzz/harness/standalone
# builds (NOT the test/oracle build). Rust/Go carry the same intent via their language flags below.
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${RUST_DEBUG_FLAGS:=-C debuginfo=2 -C force-frame-pointers=yes -C llvm-args=-gdwarf-3}"
: "${GO_DEBUG_FLAGS:=-gcflags=all=-N -l}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
# COVERAGE_FLAGS: empty by default → no effect on the normal oracle build. Set it via the Dockerfile's
# `--build-arg COVERAGE_FLAGS="-fprofile-instr-generate -fcoverage-mapping"` to instrument the TEST
# build for source-coverage measurement (how much of the project the test suite actually exercises —
# a quality signal for the oracle; complements the anti-reward-hack sabotage check). APPEND it to the
# test build's compile+link flags in step 3 (NOT the fuzz build); after `test.sh` runs, merge with
# `llvm-profdata` and report with `llvm-cov`. Empty value is honored (`=`, not `:=`).
: "${COVERAGE_FLAGS=}"
export SANITIZER_FLAGS DEBUG_FLAGS RUST_DEBUG_FLAGS GO_DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

cd "$SRC"

# Dependencies upstream's CMake would download are pre-fetched into the image (mayhem/Dockerfile):
# intx via EVMONE_INTX_DIR, google/benchmark via FETCHCONTENT_SOURCE_DIR_BENCHMARK, blst via the
# mayhem/cmake/blst.cmake override, and nlohmann_json/GoogleTest/CLI11 from apt (Hunter disabled).
# Nothing here touches the network, so the script re-runs offline.
: "${EVMONE_DEPS:=/opt/toolchains/deps}"
export EVMONE_DEPS
COMMON_CMAKE=(
  -G Ninja
  -DCMAKE_BUILD_TYPE=Release
  -DCMAKE_CXX_SCAN_FOR_MODULES=OFF
  -DHUNTER_ENABLED=OFF
  -DEVMONE_INTX_DIR="$EVMONE_DEPS/intx"
  -DFETCHCONTENT_SOURCE_DIR_BENCHMARK="$EVMONE_DEPS/benchmark"
  -DFETCHCONTENT_FULLY_DISCONNECTED=ON
  -DCMAKE_MODULE_PATH="$SRC/mayhem/cmake"
)

# (build/ is gitignored upstream, so `git clean -ffdX` resets every build dir below.)
# CMake picks the compiler up from the exported $CC/$CXX; passing -DCMAKE_*_COMPILER=clang++ again on a
# re-run mismatches the resolved path in the cache and makes CMake wipe it (non-idempotent).
mkdir -p build

# LeakSanitizer off (SPEC 6.2 item 15): ASan + UBSan stay on, only leak detection is dropped.
$CXX $SANITIZER_FLAGS $DEBUG_FLAGS -c "$SRC/mayhem/lsan_off.cc" -o build/lsan_off.o
# The libFuzzer-free run-once driver is C; compile it as C so its LLVMFuzzerTestOneInput ref is unmangled.
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o build/standalone_main.o

# 1) The fuzzer, with upstream's own fuzzing configuration (EVMONE_FUZZING + ASSERTIONS, as in its
#    circle.yml): evmone, its precompiles (incl. blst) and the test utilities are built sanitized, with
#    DWARF 3, so the fuzzed code is instrumented.
cmake -S . -B build/fuzz "${COMMON_CMAKE[@]}" \
  -DASSERTIONS=ON -DEVMONE_FUZZING=ON \
  -DCMAKE_C_FLAGS="$SANITIZER_FLAGS $DEBUG_FLAGS" \
  -DCMAKE_CXX_FLAGS="$SANITIZER_FLAGS $DEBUG_FLAGS" \
  -DCMAKE_EXE_LINKER_FLAGS="$SRC/build/lsan_off.o"
cmake --build build/fuzz -j"$MAYHEM_JOBS" --target evmone-fuzzer
cp build/fuzz/bin/evmone-fuzzer /mayhem/evmone-fuzzer

# 2) The standalone reproducer: the same harness object and libraries, linked against the run-once
#    driver instead of libFuzzer. The libraries are linked as one group, so their order does not matter.
$CXX $SANITIZER_FLAGS $DEBUG_FLAGS -fsanitize=fuzzer-no-link \
  build/fuzz/test/fuzzer/CMakeFiles/evmone-fuzzer.dir/fuzzer.cpp.o \
  build/standalone_main.o build/lsan_off.o \
  -Wl,--start-group $(find build/fuzz/lib build/fuzz/test/state build/fuzz/test/utils build/fuzz/deps/src/blst \
      -name '*.a' | sort) -Wl,--end-group \
  -o /mayhem/evmone-fuzzer-standalone

# 3) The project's own unit tests (GoogleTest), built with the project's NORMAL flags in a separate
#    tree so mayhem/test.sh only runs them.
cmake -S . -B build/tests "${COMMON_CMAKE[@]}" \
  -DEVMONE_TESTING=ON \
  -DCMAKE_C_FLAGS="$COVERAGE_FLAGS" -DCMAKE_CXX_FLAGS="$COVERAGE_FLAGS" \
  -DCMAKE_EXE_LINKER_FLAGS="$COVERAGE_FLAGS"
cmake --build build/tests -j"$MAYHEM_JOBS" --target evmone-unittests
