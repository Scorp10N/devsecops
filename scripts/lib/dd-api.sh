#!/usr/bin/env bash
# dd-api.sh — shared DefectDojo API helpers
# Source this file; do not execute directly.
# Requires: DEFECTDOJO_API_KEY in environment, jq, curl

DD_URL="${DD_URL:-http://localhost:8080}"

# dd_import_scan <product_name> <scan_type> <file_path> <engagement_name>
# POSTs a findings file to DefectDojo /api/v2/import-scan/
# Returns the HTTP response body (JSON).
dd_import_scan() {
  local product_name="$1"
  local scan_type="$2"
  local file_path="$3"
  local engagement_name="$4"

  [[ -f "${file_path}" ]] || { echo "[dd-api] SKIP: file not found: ${file_path}" >&2; return 0; }

  local response
  response=$(curl -sf -X POST \
    "${DD_URL}/api/v2/import-scan/" \
    -H "Authorization: Token ${DEFECTDOJO_API_KEY}" \
    -F "scan_type=${scan_type}" \
    -F "file=@${file_path}" \
    -F "product_name=${product_name}" \
    -F "engagement_name=${engagement_name}" \
    -F "auto_create_context=true" \
    -F "close_old_findings=true" \
    -F "push_to_jira=false") || {
      echo "[dd-api] ERROR: import-scan failed for ${product_name} / ${scan_type}" >&2
      return 1
    }

  local count
  count=$(echo "${response}" | jq -r '.test // "?" | tostring')
  echo "[dd-api] Imported ${scan_type} for ${product_name} (test_id=${count})"
}

# dd_get_product_id <product_name>
# Returns the numeric DD product ID for the given product name, or empty string.
dd_get_product_id() {
  local product_name="$1"
  curl -sf "${DD_URL}/api/v2/products/?name=${product_name}" \
    -H "Authorization: Token ${DEFECTDOJO_API_KEY}" \
    | jq -r '.results[0].id // empty'
}

# dd_posture_snapshot <output_file>
# Exports a summary of all active findings to <output_file> as JSON.
dd_posture_snapshot() {
  local output_file="$1"
  local tmp_dir
  tmp_dir=$(dirname "${output_file}")
  mkdir -p "${tmp_dir}"

  curl -sf "${DD_URL}/api/v2/findings/?active=true&limit=1000&related_fields=true" \
    -H "Authorization: Token ${DEFECTDOJO_API_KEY}" \
    | jq '{
        generated_at: now | todate,
        total_active: (.count),
        by_severity: (
          .results
          | group_by(.severity)
          | map({(.[0].severity): length})
          | add // {}
        ),
        by_product: (
          .results
          | group_by(.test_object.engagement.product.name // "unknown")
          | map({(.[0].test_object.engagement.product.name // "unknown"): length})
          | add // {}
        ),
        critical_findings: [
          .results[]
          | select(.severity == "Critical")
          | {title: .title, product: .test_object.engagement.product.name, cve: .cve}
        ]
      }' > "${output_file}"

  echo "[dd-api] Posture snapshot written to ${output_file}"
}

# dd_save_and_archive <src_file> <findings_base_dir> <repo_slug> <tool_name>
# Copies src_file to findings/<repo_slug>/latest/<tool_name>.<ext>
# and archives to findings/<repo_slug>/history/YYYY-MM-DD/<tool_name>.<ext>
dd_save_and_archive() {
  local src_file="$1"
  local findings_base="$2"
  local repo_slug="$3"
  local tool_name="$4"
  local ext="${src_file##*.}"
  local today
  today=$(date +%Y-%m-%d)

  local latest_dir="${findings_base}/${repo_slug}/latest"
  local history_dir="${findings_base}/${repo_slug}/history/${today}"
  mkdir -p "${latest_dir}" "${history_dir}"

  cp "${src_file}" "${latest_dir}/${tool_name}.${ext}"
  cp "${src_file}" "${history_dir}/${tool_name}.${ext}"
  echo "[dd-api] Saved ${tool_name}.${ext} for ${repo_slug}"
}
