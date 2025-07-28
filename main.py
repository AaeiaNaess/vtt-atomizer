from __future__ import annotations

import hashlib
import os
import re
from typing import List, Dict, Any, Tuple, Optional

from flask import Flask, request, jsonify

app = Flask(__name__)

DEFAULT_MAX_CHARS = int(os.getenv("DEFAULT_MAX_CHARS", 12_000))
HARD_MAX = 200_000
HARD_MIN = 1_000
APP_VERSION = "2025-07-25-5"


# ---------------------------
# Helpers
# ---------------------------

def normalize_newlines(text: str) -> str:
    # If the payload was double-escaped (e.g. "\\n"), unescape it
    if "\\n" in text or "\\r" in text:
        text = text.encode("utf-8").decode("unicode_escape")
    return text.replace("\r\n", "\n").replace("\r", "\n")


def split_into_blocks(vtt_text: str) -> List[str]:
    return [b for b in vtt_text.strip().split("\n\n") if b.strip()]


def chunk_blocks(blocks: List[str], max_chars: int) -> List[str]:
    chunks = []
    current = ""
    for block in blocks:
        projected_len = len(current) + (2 if current else 0) + len(block)
        if projected_len > max_chars:
            if current:
                chunks.append(current)
            if len(block) > max_chars:
                # Oversized single block: just push it as-is
                chunks.append(block)
                current = ""
            else:
                current = block
        else:
            current = block if not current else f"{current}\n\n{block}"
    if current:
        chunks.append(current)
    return chunks


def sha1(text: str) -> str:
    return hashlib.sha1(text.encode("utf-8")).hexdigest()


_speaker_re = re.compile(r'^\s*([A-Za-z][\w .\-]{0,80}):', re.MULTILINE)


def extract_speakers(vtt_text: str) -> List[str]:
    speakers = {m.group(1).strip() for m in _speaker_re.finditer(vtt_text)}
    return sorted(s for s in speakers if s)


def coerce_int(value: Any, default: int) -> int:
    try:
        v = int(value)
        return max(HARD_MIN, min(HARD_MAX, v))
    except Exception:
        return default


def headers_lowercase() -> Dict[str, str]:
    """Return all incoming headers with lowercase keys for easy, case-insensitive lookup."""
    return {k.lower(): v for k, v in request.headers.items()}


def first_non_empty(*vals):
    for v in vals:
        if v is not None and str(v).strip() != "":
            return v
    return None


def resolve_uuid_from_request(json_payload: Optional[dict]) -> Tuple[str, str, Optional[str]]:
    """
    Return (uuid, source, key_used)
    source: one of 'json', 'args', 'headers', 'environ', 'fallback'
    key_used: which key actually matched (for debugging), or None
    """
    # 1) JSON
    if json_payload:
        candidate = json_payload.get("uuid")
        if candidate and str(candidate).strip():
            return str(candidate).strip(), "json", "payload['uuid']"

    # 2) Query args
    candidate = request.args.get("uuid")
    if candidate and str(candidate).strip():
        return str(candidate).strip(), "args", "uuid (query param)"

    # 3) Headers (case-insensitive)
    #    We'll log all headers here to be explicit
    hdrs = headers_lowercase()
    for k in ("x-uuid", "uuid"):
        if k in hdrs and str(hdrs[k]).strip():
            return hdrs[k].strip(), "headers", k

    # 4) WSGI environ fallback (HTTP_X_UUID)
    env_uuid = request.environ.get("HTTP_X_UUID")
    if env_uuid and str(env_uuid).strip():
        return str(env_uuid).strip(), "environ", "HTTP_X_UUID"

    # 5) Fallback
    return "unknown_uuid", "fallback", None


# ---------------------------
# Routes
# ---------------------------

@app.route("/", methods=["POST"])
def chunk_vtt():
    max_chars = coerce_int(request.args.get("max_chars"), DEFAULT_MAX_CHARS)

    vtt_text = None
    meta: Dict[str, Any] = {}

    try:
        json_payload = None
        if request.is_json:
            json_payload = request.get_json(force=True, silent=False)
            vtt_text = (json_payload or {}).get("vtt", "")
        else:
            vtt_text = request.get_data(as_text=True)

        # DEBUG: print headers every time for now
        print("[DEBUG] Headers received:")
        for key, val in request.headers.items():
            print(f"  {key}: {val}")

        uuid, uuid_source, uuid_key = resolve_uuid_from_request(json_payload)

        print(f"[UUID-RESOLVE] resolved='{uuid}' source='{uuid_source}' key='{uuid_key}' is_json={request.is_json}")

        if request.is_json:
            meta = {
                "uuid": uuid,
                "title": (json_payload or {}).get("title", "Untitled Meeting"),
                "row_number": (json_payload or {}).get("row_number"),
                "sheet": (json_payload or {}).get("sheet"),
                "spreadsheet_id": (json_payload or {}).get("spreadsheet_id"),
                "extra": (json_payload or {}).get("extra", {}),
                "source": "json",
                "uuid_source": uuid_source,
                "uuid_key": uuid_key,
            }
        else:
            hdrs = headers_lowercase()
            meta = {
                "uuid": uuid,
                "title": hdrs.get("x-title", "Untitled Meeting"),
                "row_number": hdrs.get("x-row-number"),
                "sheet": hdrs.get("x-sheet"),
                "spreadsheet_id": hdrs.get("x-spreadsheet-id"),
                "extra": {},
                "source": "headers",
                "uuid_source": uuid_source,
                "uuid_key": uuid_key,
            }

        if not vtt_text or not vtt_text.strip():
            raise ValueError("Empty or missing VTT")

        vtt_text = normalize_newlines(vtt_text)
        blocks = split_into_blocks(vtt_text)
        chunks = chunk_blocks(blocks, max_chars=max_chars)

        transcript_hash = sha1(vtt_text)
        speakers = extract_speakers(vtt_text)

        enriched_chunks = []
        for idx, text in enumerate(chunks, start=1):
            enriched_chunks.append({
                "chunk_index": idx,
                "chunk_text": text,
                "uuid": meta.get("uuid"),
                "title": meta.get("title"),
                "row_number": meta.get("row_number"),
                "sheet": meta.get("sheet"),
                "spreadsheet_id": meta.get("spreadsheet_id"),
                "transcript_hash": transcript_hash,
                "total_chunks": len(chunks),
            })

        print(
            f"[OK] Chunks created: {len(enriched_chunks)} | UUID: {meta.get('uuid')} | "
            f"UUID source: {uuid_source} | key: {uuid_key} | Source: {meta.get('source')}"
        )

        return jsonify({
            "version": APP_VERSION,
            "max_chars_used": max_chars,
            "chunk_count": len(enriched_chunks),
            "avg_chunk_len": int(sum(len(c["chunk_text"]) for c in enriched_chunks) / len(enriched_chunks)) if enriched_chunks else 0,
            "speakers": speakers,
            "transcript_hash": transcript_hash,
            "meta": meta,
            "chunks": enriched_chunks,
        })

    except Exception as e:
        print(f"[ERROR] chunk_vtt failed: {e}")
        return jsonify({"error": str(e)}), 400


@app.route("/health", methods=["GET"])
def health():
    return "OK", 200


@app.route("/version", methods=["GET"])
def version():
    return jsonify({"version": APP_VERSION}), 200


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "8080")))
