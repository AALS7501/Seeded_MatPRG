#!/usr/bin/env bash
# Usage:
#   ./run_bench.sh                          # DATA_LOG=5..10, all versions
#   ./run_bench.sh --data-log 7             # DATA_LOG=7 only, all versions
#   ./run_bench.sh --version 3              # DATA_LOG=5..10, version 3 only
#   ./run_bench.sh --data-log 7 --version 3 # DATA_LOG=7, version 3 only

DATA_LOG_ARG=""
VERSION_ARG=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --data-log) DATA_LOG_ARG="$2"; shift 2 ;;
        --version)  VERSION_ARG="$2";  shift 2 ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

if [[ -n "${DATA_LOG_ARG}" ]]; then
    DATA_LOGS=("${DATA_LOG_ARG}")
else
    DATA_LOGS=(5 6 7 8 9 10)
fi

TIMESTAMP=$(date +"%y%m%d_%H%M%S")
OUTPUT="bench_results/registerdata_${TIMESTAMP}.txt"

echo "=== registerdata benchmark  $(date) ===" | tee "${OUTPUT}"
[[ -n "${VERSION_ARG}" ]] && echo "version: ${VERSION_ARG}" | tee -a "${OUTPUT}"
echo "" | tee -a "${OUTPUT}"

for DATA_LOG in "${DATA_LOGS[@]}"; do
    echo "----------------------------------------" | tee -a "${OUTPUT}"
    echo "DATA_LOG=${DATA_LOG}  ($(( 1 << DATA_LOG )) KB)" | tee -a "${OUTPUT}"
    echo "----------------------------------------" | tee -a "${OUTPUT}"

    export DATA_LOG
    [[ -n "${VERSION_ARG}" ]] && export VERSION="${VERSION_ARG}" || unset VERSION

    cargo bench \
        --features registerdata,parallel \
        --bench registerdata \
        2>&1 | grep -v "^warning" | tee -a "${OUTPUT}"

    echo "" | tee -a "${OUTPUT}"
done

echo "=== done  $(date) ===" | tee -a "${OUTPUT}"
echo ""
echo "Saved to ${OUTPUT}"
