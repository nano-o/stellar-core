#!/usr/bin/env bash

set -euo pipefail

script_dir="$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)"
repo_root="$(CDPATH='' cd -- "$script_dir/../.." && pwd)"
stellar_core_dir="$repo_root"
golden_dir="$script_dir/golden"
golden_tsv="$golden_dir/expected.tsv"
golden_rows_per_tag=40

# The model side runs through the generic runner of the Isabelle tooling clone
# (build, export, ML_process, framing, row alignment); this repo supplies the
# corpus, the dispatch ML named by isabelle-tooling.conf, the cross-record
# checks below, the C++ comparison, and the mutation policy.
tooling_root="${ISABELLE_TOOLING_ROOT:-}"
if [[ -z "$tooling_root" || ! -x "$tooling_root/scripts/model-runner.sh" ]]; then
    echo "ISABELLE_TOOLING_ROOT must name a clone of isabelle-formal-modeling-tooling" >&2
    exit 1
fi
model_runner="$tooling_root/scripts/model-runner.sh"

work_dir="$(mktemp -d "${TMPDIR:-/tmp}/isabelle-offer-exchange.XXXXXX")"
if [[ -z "$work_dir" || ! -d "$work_dir" ]]; then
    echo "Could not create a differential-test working directory" >&2
    exit 1
fi

finish()
{
    status=$?
    if [[ "$status" -eq 0 ]]; then
        rm -rf -- "$work_dir"
    else
        echo "Differential-test artifacts preserved at $work_dir" >&2
    fi
}
trap finish EXIT

input_tsv="$work_dir/input.tsv"
model_tsv="$work_dir/model.tsv"
expected_tsv="$work_dir/expected.tsv"
cpp_log="$work_dir/cpp-comparison.log"

# Extra options for the Isabelle build, for example
# ISABELLE_OFFER_EXCHANGE_BUILD_OPTIONS="-o quick_and_dirty" while an
# unrelated theory of the session still carries a sorry.  Isabelle's own
# settings reset ISABELLE_BUILD_OPTIONS, so that variable cannot be used.
read -r -a isabelle_build_options <<<"${ISABELLE_OFFER_EXCHANGE_BUILD_OPTIONS:-}"
runner_options=()
for build_option in "${isabelle_build_options[@]}"; do
    if [[ "$build_option" == "-o" ]]; then
        continue
    fi
    runner_options+=(-o "${build_option#-o}")
done

echo "Generating deterministic corpus"
python3 "$script_dir/generate_cases.py" "$input_tsv"

# Cross-record structure is harness business, not the dispatch ML's: every
# case_id must be unique across the corpus.
duplicate_case_id="$(
    awk -F '\t' 'substr($0, 1, 1) != "#" && length($0) > 0 && seen[$3]++ == 1 { print $3; exit }' \
        "$input_tsv"
)"
if [[ -n "$duplicate_case_id" ]]; then
    echo "Corpus contains a duplicate case_id: $duplicate_case_id" >&2
    exit 1
fi

echo "Evaluating generated SML model"
"$model_runner" --project-root "$repo_root" --work-dir "$work_dir/model-runner" \
    "${runner_options[@]}" batch "$input_tsv" "$model_tsv"

# Every output row is the input row followed by a status field and then the
# result fields, so the column layout is fully determined by the input arity.
# Emit one #schema line per tag ahead of its first row, derived from the input
# record itself, so consumers never hardcode column numbers that rot when a
# field is added.  The runner echoes the corpus comments; drop them here so
# the result file keeps the shape it had before the runner existed.
awk -F '\t' '
    BEGIN { OFS = "\t" }
    substr($0, 1, 1) == "#" || length($0) == 0 { next }
    FNR == NR { if (!($2 in arity)) arity[$2] = NF; next }
    !($2 in schema_done) {
        schema_done[$2] = 1
        print "#schema", $2, arity[$2] + 1, arity[$2] + 2
    }
    { print }
' "$input_tsv" "$model_tsv" > "$expected_tsv"

input_count="$(
    awk 'length($0) > 0 && substr($0, 1, 1) != "#" { count += 1 }
         END { print count + 0 }' "$input_tsv"
)"
output_count="$(
    awk 'length($0) > 0 && substr($0, 1, 1) != "#" { count += 1 }
         END { print count + 0 }' "$expected_tsv"
)"
if [[ "$input_count" -ne "$output_count" ]]; then
    echo "Model produced $output_count rows for $input_count input records" >&2
    exit 1
fi

# Lifecycle records have 13 input fields followed by OK and exactly 27 model
# values: 41 TSV fields total, or 28 output fields when OK is counted.  Keep
# the two operation directions isolated and require every important stage in
# each 211-row per-protocol corpus so an
# early-exit-only tag cannot appear complete.
lifecycle_tags=(offer_lifecycle_sell offer_lifecycle_buy)
# Lifecycle rows are generated at protocols 28 and 29, each against its own
# real ledger; see generate_cases.py and ExchangeTests.cpp.
lifecycle_versions=(28 29)
for lifecycle_tag in "${lifecycle_tags[@]}"; do
    for lifecycle_version in "${lifecycle_versions[@]}"; do
        coverage="$({
            awk -F '\t' -v tag="$lifecycle_tag" -v ver="$lifecycle_version" '
                substr($0, 1, 1) != "#" && $2 == tag && $6 == ver {
                    count += 1
                    if (NF != 41) bad_arity += 1
                    if ($15 >= 1 && $15 <= 4) posting_rejected += 1
                    if ($16 == 1) offer_created += 1
                    if ($25 == 1) limit_changed += 1
                    if ($28 == 1 && $29 > 0 && $30 > 0) positive_cross += 1
                }
                END {
                    print count + 0, bad_arity + 0, posting_rejected + 0,
                        offer_created + 0, limit_changed + 0, positive_cross + 0
                }' "$expected_tsv"
        })"
        read -r lifecycle_count bad_arity posting_rejected offer_created \
            limit_changed positive_cross <<<"$coverage"
        label="$lifecycle_tag at protocol $lifecycle_version"
        if [[ "$lifecycle_count" -ne 211 ]]; then
            echo "$label has $lifecycle_count rows; expected 211" >&2
            exit 1
        fi
        if [[ "$bad_arity" -ne 0 ]]; then
            echo "$label has $bad_arity rows without exactly 41 fields" >&2
            exit 1
        fi
        if [[ "$posting_rejected" -eq 0 ]]; then
            echo "$label has no ordinary posting rejection" >&2
            exit 1
        fi
        if [[ "$offer_created" -eq 0 ]]; then
            echo "$label has no created offer" >&2
            exit 1
        fi
        if [[ "$limit_changed" -eq 0 ]]; then
            echo "$label has no admissible limit change" >&2
            exit 1
        fi
        if [[ "$positive_cross" -eq 0 ]]; then
            echo "$label has no successful positive crossing" >&2
            exit 1
        fi
        printf '%s coverage: %s rows; posting-rejected=%s created=%s ' \
            "$label" "$lifecycle_count" "$posting_rejected" "$offer_created"
        printf 'limit-changed=%s positive-cross=%s\n' \
            "$limit_changed" "$positive_cross"
    done
done

if [[ -n "${STELLAR_CORE_BIN:-}" ]]; then
    if [[ ! -x "$STELLAR_CORE_BIN" ]]; then
        echo "STELLAR_CORE_BIN is not an executable file: $STELLAR_CORE_BIN" >&2
        exit 1
    fi
    stellar_core_bin="$(realpath "$STELLAR_CORE_BIN")"
else
    if [[ ! -f "$stellar_core_dir/Makefile" ]] ||
        ! rg -q '^am__append_[0-9]+ = -DBUILD_TESTS=1$' \
            "$stellar_core_dir/Makefile"
    then
        echo "stellar-core is configured without tests; reconfigure without --disable-tests" >&2
        exit 1
    fi
    echo "Building stellar-core test binary"
    (
        cd "$stellar_core_dir"
        make ALL_SOROBAN_GIT_STATE_STAMPS=
    )
    stellar_core_bin="$stellar_core_dir/src/stellar-core"
fi

echo "Comparing Isabelle with C++"
if ! (
    cd "$stellar_core_dir"
    ISABELLE_OFFER_EXCHANGE_EXPECTED="$expected_tsv" \
        "$stellar_core_bin" test '[isabelle-offer-exchange]'
) >"$cpp_log" 2>&1
then
    tail -n 120 "$cpp_log" >&2
    exit 1
fi
if ! rg -q 'All tests passed .* in 1 test case' "$cpp_log"; then
    echo "The stellar-core binary did not run exactly one passing differential test" >&2
    tail -n 120 "$cpp_log" >&2
    exit 1
fi

record_tags=(
    offer_value
    offer_amount_from_value
    big_multiply
    price_error_bound
    big_divide
    big_divide_128
    big_multiply_unsigned
    big_divide_unsigned
    big_divide_nothrow
    big_divide_unsigned_128
    big_divide_128_nothrow
    apply_price_error_thresholds
    exchange_v10_without_price_error_thresholds
    exchange_v10
    adjust_offer
    offer_selling_liabilities
    offer_buying_liabilities
    offer_lifecycle_sell
    offer_lifecycle_buy
)
for record_tag in "${record_tags[@]}"; do
    altered_tsv="$work_dir/expected-altered-$record_tag.tsv"
    nonvacuity_log="$work_dir/nonvacuity-$record_tag.log"
    awk -F '\t' -v tag="$record_tag" '
        BEGIN { OFS = "\t"; status_column = 0; value_column = 0 }
        substr($0, 1, 1) == "#" {
            if ($1 == "#schema" && $2 == tag) {
                status_column = $3 + 0
                value_column = $4 + 0
            }
            print
            next
        }
        $2 == tag && changed == 0 && status_column > 0 {
            if ($status_column == "OK") {
                if ((tag == "offer_lifecycle_sell" ||
                     tag == "offer_lifecycle_buy") &&
                    $15 == 12 && $28 == 1 && $29 > 0 && $30 > 0) {
                    # Corrupt the successful wheat transfer, not an early
                    # stage flag, so each lifecycle tag proves that a real
                    # successful-result field is compared independently.
                    $29 = $29 "0"
                    changed = 1
                } else if (tag == "price_error_bound") {
                    $value_column = ($value_column == "0") ? "1" : "0"
                    changed = 1
                } else {
                    $value_column = $value_column "0"
                    changed = 1
                }
            }
        }
        { print }
        END {
            if (status_column == 0) exit 3
            if (changed == 0) exit 2
        }' \
        "$expected_tsv" > "$altered_tsv"

    if (
        cd "$stellar_core_dir"
        ISABELLE_OFFER_EXCHANGE_EXPECTED="$altered_tsv" \
            "$stellar_core_bin" test '[isabelle-offer-exchange]'
    ) >"$nonvacuity_log" 2>&1
    then
        echo "An altered $record_tag result unexpectedly passed C++ comparison" >&2
        exit 1
    fi
done

# Which failure fires is part of the specification, so an ERR row's error
# code is a compared result field too.  Every tag that produces ERR rows must
# have one ERR row whose code is rotated to another valid code and rejected by
# C++; rotating rather than corrupting keeps the row parseable, so the rejection
# comes from the comparison and not from a parse failure.  The tags without ERR
# rows are fixed here so a corpus that silently loses its failure coverage is a
# failure rather than a skipped check.
tags_without_err_rows=(
    big_multiply_unsigned
    offer_lifecycle_sell
    offer_lifecycle_buy
)
for record_tag in "${record_tags[@]}"; do
    err_rows="$(
        awk -F '\t' -v tag="$record_tag" '
            BEGIN { status_column = 0 }
            $1 == "#schema" && $2 == tag { status_column = $3 + 0; next }
            substr($0, 1, 1) == "#" { next }
            $2 == tag && status_column > 0 && $status_column == "ERR" { count += 1 }
            END { print count + 0 }' "$expected_tsv"
    )"
    expect_none=0
    for tag_without in "${tags_without_err_rows[@]}"; do
        [[ "$tag_without" == "$record_tag" ]] && expect_none=1
    done
    if [[ "$expect_none" -eq 1 ]]; then
        if [[ "$err_rows" -ne 0 ]]; then
            echo "$record_tag now produces $err_rows ERR rows; add it to the ERR mutation set" >&2
            exit 1
        fi
        continue
    fi
    if [[ "$err_rows" -eq 0 ]]; then
        echo "$record_tag produces no ERR rows; the corpus lost its failure coverage" >&2
        exit 1
    fi

    altered_tsv="$work_dir/expected-altered-err-$record_tag.tsv"
    nonvacuity_log="$work_dir/nonvacuity-err-$record_tag.log"
    awk -F '\t' -v tag="$record_tag" '
        BEGIN { OFS = "\t"; status_column = 0; value_column = 0 }
        substr($0, 1, 1) == "#" {
            if ($1 == "#schema" && $2 == tag) {
                status_column = $3 + 0
                value_column = $4 + 0
            }
            print
            next
        }
        $2 == tag && changed == 0 && status_column > 0 &&
            $status_column == "ERR" {
            if ($value_column == "ASSERTION") $value_column = "OVERFLOW"
            else if ($value_column == "OVERFLOW") $value_column = "RUNTIME"
            else if ($value_column == "RUNTIME") $value_column = "ASSERTION"
            else exit 4
            changed = 1
        }
        { print }
        END {
            if (status_column == 0) exit 3
            if (changed == 0) exit 2
        }' \
        "$expected_tsv" > "$altered_tsv"

    if (
        cd "$stellar_core_dir"
        ISABELLE_OFFER_EXCHANGE_EXPECTED="$altered_tsv" \
            "$stellar_core_bin" test '[isabelle-offer-exchange]'
    ) >"$nonvacuity_log" 2>&1
    then
        echo "An altered $record_tag error code unexpectedly passed C++ comparison" >&2
        exit 1
    fi
done

# Update the no-Isabelle golden only after every tag's independent altered
# result has been rejected by C++.
if [[ -n "${UPDATE_GOLDEN:-}" ]]; then
    mkdir -p -- "$golden_dir"
    awk -F '\t' -v per_tag="$golden_rows_per_tag" '
        substr($0, 1, 1) == "#" { print; next }
        { if (++seen[$2] <= per_tag) print }' \
        "$expected_tsv" > "$golden_tsv"
    golden_count="$(
        awk 'length($0) > 0 && substr($0, 1, 1) != "#" { count += 1 }
             END { print count + 0 }' "$golden_tsv"
    )"
    echo "Wrote $golden_count-record golden corpus to $golden_tsv"
fi

echo "Differential test passed: $input_count cases; per-tag altered OK and ERR results failed as expected"
