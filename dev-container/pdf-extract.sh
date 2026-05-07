#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF' >&2
Usage: pdf-extract [--ocr] <input.pdf> [output.txt]

Extract text from a PDF to stdout or a file. By default it tries embedded text
first and falls back to OCR if needed. Use --ocr to force OCR.
EOF
  exit 2
}

force_ocr=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --ocr)
      force_ocr=1
      shift
      ;;
    --help|-h)
      usage
      ;;
    --)
      shift
      break
      ;;
    -*)
      echo "Unknown option: $1" >&2
      usage
      ;;
    *)
      break
      ;;
  esac
done

if [[ $# -lt 1 || $# -gt 2 ]]; then
  usage
fi

input_pdf="$1"
output_path="${2:-}"

if [[ ! -f "${input_pdf}" ]]; then
  echo "PDF not found: ${input_pdf}" >&2
  exit 1
fi

tmpdir="$(mktemp -d)"
cleanup() {
  rm -rf "${tmpdir}"
}
trap cleanup EXIT

normalized_pdf="${tmpdir}/normalized.pdf"
if ! qpdf --warning-exit-0 --decrypt "${input_pdf}" "${normalized_pdf}" >/dev/null 2>&1; then
  cp "${input_pdf}" "${normalized_pdf}"
fi

emit_output() {
  if [[ -n "${output_path}" ]]; then
    cat > "${output_path}"
  else
    cat
  fi
}

has_text() {
  [[ -n "$(printf '%s' "$1" | tr -d '[:space:]')" ]]
}

extract_embedded_text() {
  local text=""

  if text="$(pdftotext -layout -enc UTF-8 "${normalized_pdf}" - 2>/dev/null)" && has_text "${text}"; then
    printf '%s' "${text}"
    return 0
  fi

  if text="$(mutool draw -F text "${normalized_pdf}" 2>/dev/null)" && has_text "${text}"; then
    printf '%s' "${text}"
    return 0
  fi

  return 1
}

extract_with_ocr() {
  local image_path=""
  local first_page=1

  pdftoppm -r 200 -gray -png "${normalized_pdf}" "${tmpdir}/page" >/dev/null 2>&1

  while IFS= read -r image_path; do
    if [[ "${first_page}" -eq 0 ]]; then
      printf '\f\n'
    fi

    tesseract "${image_path}" stdout -l eng 2>/dev/null
    first_page=0
  done < <(find "${tmpdir}" -maxdepth 1 -type f -name 'page-*.png' | sort -V)

  if [[ "${first_page}" -eq 1 ]]; then
    return 1
  fi

  return 0
}

if [[ -z "${force_ocr}" ]]; then
  if extract_embedded_text | emit_output; then
    exit 0
  fi
fi

if extract_with_ocr | emit_output; then
  exit 0
fi

echo "Failed to extract text from ${input_pdf}" >&2
exit 1
