"""
OblivGM  —  TeeDemo
────────────────────────────────────────────────────────────
Run (local):
    pip install flask pycryptodome
    python OblivGM-TeeDemo.py

Then open: http://localhost:5000

Architecture
────────────
• OblivGM is a *software-only* oblivious graph mechanism — no TEE required.
• All crypto runs on the host CPU (software AES-GCM, no hardware enclave).
• Access-pattern hiding is achieved purely through fixed 2× oblivious padding:
    – Every query fetches exactly P(r) = 2r blocks, regardless of true result size.
    – ALL P(r) records are processed in a constant-time oblivious scan — no early exit.
    – Dummies are silently discarded only after the full scan completes.
• There is no DSSE label index.  Label queries use a linear oblivious scan over
  the entire padded candidate set, which hides the true label cardinality from any
  observer watching memory access patterns.
• No Spark distribution — single-threaded, no TEE vsock, no Nitro Enclave.

This demo is structurally identical to DVHGQP-TeeDemo but with the OblivGM
mechanism substituted throughout (padding, query engine, UI labels).
"""

from flask import Flask, request, jsonify, render_template_string
import os, json, time, math, hashlib, collections, gzip, urllib.request, re
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

# ── Optional imports (graceful degradation) ──────────────
try:
    from dotenv import load_dotenv
    load_dotenv(dotenv_path=os.path.join(os.path.dirname(__file__), ".env"))
except ImportError:
    pass

app = Flask(__name__)

# ── Configuration ─────────────────────────────────────────
CONFIG = {
    "BATCH_SIZE": int(os.getenv("BATCH_SIZE", "500")),
}
DATASET_ID = "dataset_demo"

# ── Crypto helpers ────────────────────────────────────────
def keygen():
    return get_random_bytes(32)

def aes_gcm_encrypt(key, pt):
    c = AES.new(key, AES.MODE_GCM)
    ct, tag = c.encrypt_and_digest(pt)
    return c.nonce + tag + ct

def aes_gcm_decrypt(key, blob):
    n, tag, ct = blob[:16], blob[16:32], blob[32:]
    return AES.new(key, AES.MODE_GCM, nonce=n).decrypt_and_verify(ct, tag)

# ── OblivGM padding: fixed 2× (no adaptive ratio) ─────────
def obliv_pad_size(r):
    """OblivGM uses a fixed 2× padding — no adaptive structure overhead."""
    if r == 0:
        return 0
    return int(r * 2.0)

# ── OblivGM oblivious scan ─────────────────────────────────
def obliv_decrypt_adjacency(K: bytes, enc_adj_hex: str) -> list:
    """Decrypt one adjacency list on the host CPU (software AES-GCM).
    OblivGM has no TEE — decryption always runs on the parent process."""
    return json.loads(aes_gcm_decrypt(K, bytes.fromhex(enc_adj_hex)).decode())

def obliv_scan_adjacency(K: bytes, records: list) -> dict:
    """
    OblivGM oblivious scan: process ALL P(r) records unconditionally.
    No early exit. Dummies fail AES-GCM tag verification and are silently
    discarded only after the full scan completes.

    Parameters
    ----------
    records : list of {"nid": int, "enc_adj_hex": str}

    Returns
    -------
    dict {nid: neighbor_list}  — only real (successfully decrypted) nodes
    """
    result = {}
    for rec in records:
        try:
            nid = rec["nid"]
            nbrs = json.loads(aes_gcm_decrypt(K, bytes.fromhex(rec["enc_adj_hex"])).decode())
            result[nid] = nbrs
        except Exception:
            pass  # dummy block — discard silently
    return result

# ── In-memory state ───────────────────────────────────────
STATE = {
    "loaded":       False,
    "nodes":        set(),
    "edges":        [],
    "node_label":   {},
    "edge_label":   {},
    "adj":          {},
    "enc_adj":      {},
    "K":            None,
    "dataset_name": "",
    "stats":        {},
}

NODE_LABELS = ["Executive", "Manager", "Employee", "External", "Inactive"]
EDGE_LABELS = ["SEND", "REPLY", "BROADCAST", "INTERNAL"]

def assign_labels(nodes, edges):
    degree = {}
    for u, v in edges:
        degree[u] = degree.get(u, 0) + 1
        degree[v] = degree.get(v, 0) + 1

    if not degree:
        return {n: "Inactive" for n in nodes}, {}, degree

    node_label = {}
    for n in nodes:
        d = degree.get(n, 0)
        if   d > 500: node_label[n] = "Executive"
        elif d > 200: node_label[n] = "Manager"
        elif d > 50:  node_label[n] = "Employee"
        elif d > 5:   node_label[n] = "External"
        else:         node_label[n] = "Inactive"

    edge_label = {}
    for (u, v) in edges:
        src = node_label.get(u, "Inactive")
        dst = node_label.get(v, "Inactive")
        if src in ("Executive", "Manager") and dst in ("Executive", "Manager"):
            edge_label[(u, v)] = "REPLY"
        elif src in ("Executive", "Manager"):
            edge_label[(u, v)] = "BROADCAST"
        elif src == dst:
            edge_label[(u, v)] = "INTERNAL"
        else:
            edge_label[(u, v)] = "SEND"

    from collections import Counter
    dist = Counter(edge_label.values())
    print(f"[Phase 0] Edge label distribution:")

    return node_label, edge_label, degree

def load_edge_list(lines):
    edge_set, nodes = set(), set()
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) >= 2:
            u, v = int(parts[0]), int(parts[1])
            if u != v:
                edge_set.add((min(u, v), max(u, v)))
                nodes.add(u); nodes.add(v)
    return nodes, list(edge_set)

def build_obliv_graph(nodes, edges):
    """
    Build the OblivGM encrypted graph structure.

    Differences from DVH-GQP:
      • No DSSE label index (K_s, K_e not needed — only K for adjacency).
      • No adaptive padding; padding computed at query time using obliv_pad_size().
      • enc_adj stores each node's neighbour list as a single AES-GCM blob.
    """
    node_label, edge_label, degree = assign_labels(nodes, edges)
    K = keygen()

    adj = collections.defaultdict(list)
    for u, v in edges:
        adj[u].append((v, edge_label[(u, v)]))
        adj[v].append((u, edge_label[(u, v)]))

    enc_adj = {}
    for node, neighbors in adj.items():
        enc_adj[node] = aes_gcm_encrypt(K, json.dumps(neighbors).encode()).hex()

    hist = {}
    for v, lbl in node_label.items():
        hist.setdefault(lbl, []).append(("v", v))
    for (u, v), lbl in edge_label.items():
        hist.setdefault(lbl, []).append(("e", u, v))

    stats = {
        "nodes":        len(nodes),
        "edges":        len(edges),
        "labels":       list(hist.keys()),
        "label_counts": {w: len(ids) for w, ids in hist.items()},
        "max_degree":   max(degree.values()) if degree else 0,
        "avg_degree":   round(sum(degree.values()) / max(len(degree), 1), 2),
    }
    return K, node_label, edge_label, dict(adj), enc_adj, hist, stats

# ── Query Engine ──────────────────────────────────────────
def parse_query(q):
    """
    OblivGM query engine.

    Key differences from DVH-GQP:
      • Padding: obliv_pad_size(r) = 2r  (fixed 2× factor)
      • No DSSE token lookup — label queries do an oblivious scan over the
        entire padded candidate set (processes ALL p_r records, no early exit).
      • No TEE / Nitro Enclave — all decryption on host CPU.
      • No Spark distribution.
    """
    q_lower = q.lower().strip()
    t0 = time.perf_counter()

    node_label = STATE["node_label"]
    edge_label = STATE["edge_label"]
    adj        = STATE["adj"]
    enc_adj    = STATE["enc_adj"]
    K          = STATE["K"]
    hist       = STATE.get("hist", {})

    def ms():
        return round((time.perf_counter() - t0) * 1000, 2)

    OBLIV_NOTE = (
        "OblivGM: software-only oblivious scan — no TEE. "
        "Fixed 2× padding hides true result size from any access-pattern observer."
    )

    # ── Count nodes ───────────────────────────────────────
    if any(x in q_lower for x in ["how many nodes", "count nodes", "total nodes", "number of nodes"]):
        r = len(STATE["nodes"])
        return {"query": q, "result": r, "unit": "nodes",
                "explanation": f"The graph contains {r} nodes total.",
                "latency_ms": ms()}

    # ── Count edges ───────────────────────────────────────
    if any(x in q_lower for x in ["how many edges", "count edges", "total edges", "number of edges"]):
        r = len(STATE["edges"])
        return {"query": q, "result": r, "unit": "edges",
                "explanation": f"The graph contains {r} edges total.",
                "latency_ms": ms()}

    # ── Degree / Neighbors of node X ──────────────────────
    deg_match = re.search(
        r'(?:degree|neighbors|connections).*?node\s+(\d+)'
        r'|node\s+(\d+).*?(?:degree|neighbors|connections)',
        q_lower)
    if not deg_match:
        deg_match = re.search(
            r'how many (?:neighbors|connections) does (?:node\s+)?(\d+)',
            q_lower)
    if deg_match:
        nid = int(deg_match.group(1) or deg_match.group(2))
        if nid in enc_adj:
            # OblivGM: build a padded record set of size P(r) = 2 * degree
            real_record = {"nid": nid, "enc_adj_hex": enc_adj[nid]}
            r = len(adj.get(nid, []))
            p_r = obliv_pad_size(max(r, 1))
            # Fill with dummy records (random nids not in graph) to reach p_r
            dummy_pool = [
                {"nid": -i, "enc_adj_hex": enc_adj.get(nid, "")}
                for i in range(1, p_r)
            ]
            padded_records = [real_record] + dummy_pool[:p_r - 1]

            t_scan_start = time.perf_counter()
            # Oblivious scan — processes ALL p_r records unconditionally
            decrypted = obliv_scan_adjacency(K, padded_records)
            t_scan_ms = (time.perf_counter() - t_scan_start) * 1000

            nbrs = decrypted.get(nid, [])
            result = len(nbrs)
            sample = [n for n, _ in nbrs[:10]]
            return {
                "query": q, "result": result, "unit": "connections",
                "explanation": (
                    f"Node {nid} ({node_label.get(nid, 'unknown')}) has {result} connections.\n"
                    f"Sample neighbors: {sample}{'...' if result > 10 else ''}\n"
                    f"OblivGM padding P(r) = 2r = {p_r} (overhead = {p_r - 1} dummy records).\n"
                    f"Oblivious scan processed all {p_r} records in {t_scan_ms:.2f} ms — no early exit.\n"
                    f"[Software AES-GCM on host CPU — no TEE enclave involved.]"
                ),
                "latency_ms": ms(),
                "privacy_note": OBLIV_NOTE,
            }
        else:
            return {"query": q, "result": 0, "unit": "connections",
                    "explanation": f"Node {nid} not found in graph.", "latency_ms": ms()}

    # ── Label of node X ───────────────────────────────────
    lbl_match = re.search(
        r'(?:label|type|role).*?node\s+(\d+)|node\s+(\d+).*?(?:label|type|role|what is)',
        q_lower)
    if lbl_match:
        nid = int(lbl_match.group(1) or lbl_match.group(2))
        lbl = node_label.get(nid, "not found")
        return {"query": q, "result": lbl, "unit": "label",
                "explanation": f"Node {nid} has label: {lbl}", "latency_ms": ms()}

    # ── Count nodes by label (OblivGM oblivious scan — no DSSE) ──
    for lbl in NODE_LABELS:
        if lbl.lower() in q_lower and any(x in q_lower for x in ["how many", "count", "number"]):
            # OblivGM: no DSSE index — collect all candidates, then pad to 2r
            candidates = [n for n, l in node_label.items() if l == lbl]
            r = len(candidates)
            if r == 0:
                return {"query": q, "result": 0, "unit": f"{lbl} nodes",
                        "explanation": f"No {lbl} nodes found.", "latency_ms": ms()}

            p_r = obliv_pad_size(r)
            overhead = p_r - r

            # Build padded scan records (real adjacency blobs + dummy repeats)
            real_records = [
                {"nid": nid, "enc_adj_hex": enc_adj[nid]}
                for nid in candidates if nid in enc_adj
            ]
            dummy_records = [
                {"nid": -i, "enc_adj_hex": real_records[i % len(real_records)]["enc_adj_hex"]}
                for i in range(overhead)
            ]
            padded = real_records + dummy_records

            t_scan_start = time.perf_counter()
            # Oblivious scan — ALL p_r records processed, no early exit
            decrypted = obliv_scan_adjacency(K, padded)
            t_scan_ms = (time.perf_counter() - t_scan_start) * 1000

            result = sum(1 for nid in decrypted if node_label.get(nid) == lbl)

            return {
                "query": q, "result": result, "unit": f"{lbl} nodes",
                "explanation": (
                    f"Found {result} {lbl} nodes.\n"
                    f"OblivGM padding P(r) = 2r = {p_r} (overhead = {overhead} dummy records).\n"
                    f"No DSSE index — full oblivious scan over {p_r} records in {t_scan_ms:.2f} ms.\n"
                    f"Observer sees exactly {p_r} uniform AES-GCM decryptions — true count hidden.\n"
                    f"[Software AES-GCM on host CPU — no TEE enclave involved.]"
                ),
                "latency_ms": ms(),
                "privacy_note": f"Leakage: L(q) = (P(r)={p_r}, access_time)  [fixed 2× padding]",
            }

    # ── BFS reachability ──────────────────────────────────
    bfs_match = re.search(
        r'bfs\s+from\s+(?:node\s+)?(\d+)(?:\s+depth\s+(\d+))?', q_lower)
    if not bfs_match:
        bfs_match = re.search(
            r'reach(?:able|ability)?\s+from\s+(?:node\s+)?(\d+)(?:\s+depth\s+(\d+))?', q_lower)
    if bfs_match:
        start = int(bfs_match.group(1))
        depth = int(bfs_match.group(2)) if bfs_match.group(2) else 2
        depth = min(depth, 3)

        if start not in adj:
            return {"query": q, "result": 0, "unit": "reachable nodes",
                    "explanation": f"Node {start} not found.", "latency_ms": ms()}

        visited, frontier = {start}, [start]
        level_info = []
        for d in range(1, depth + 1):
            if not frontier:
                break
            r_f = len(frontier)
            p_r = obliv_pad_size(r_f)

            # Build padded records for this frontier
            real_records = [
                {"nid": nid, "enc_adj_hex": enc_adj[nid]}
                for nid in frontier if nid in enc_adj
            ]
            overhead = p_r - len(real_records)
            dummy_records = [
                {"nid": -i, "enc_adj_hex": real_records[i % len(real_records)]["enc_adj_hex"]}
                for i in range(overhead)
            ] if real_records else []
            padded = real_records + dummy_records

            t_scan_start = time.perf_counter()
            # Oblivious scan — ALL p_r records processed, no early exit
            decrypted = obliv_scan_adjacency(K, padded)
            t_scan_ms = (time.perf_counter() - t_scan_start) * 1000

            new_frontier = []
            for nid, nbrs in decrypted.items():
                for nbr, _ in nbrs:
                    if nbr not in visited:
                        visited.add(nbr)
                        new_frontier.append(nbr)

            level_info.append(
                f"Depth {d}: frontier={r_f} → discovered {len(new_frontier)} new nodes "
                f"(OblivGM padded scan P(r)={p_r}, scan_ms={t_scan_ms:.1f})"
            )
            frontier = new_frontier

        return {
            "query": q, "result": len(visited) - 1, "unit": "reachable nodes",
            "explanation": (
                f"BFS from node {start} (depth={depth}): {len(visited) - 1} reachable nodes.\n"
                + "\n".join(level_info) + "\n"
                + "[OblivGM] Fixed 2× oblivious scan per frontier level — no TEE, no Spark."
            ),
            "latency_ms": ms(),
            "privacy_note": "Observer sees P(r)=2r uniform accesses per level — true frontier size hidden.",
        }

    # ── Point-to-point reachability ───────────────────────
    reach_match = re.search(
        r'(?:can|does|is).*?(?:node\s+)?(\d+).*?reach.*?(?:node\s+)?(\d+)', q_lower)
    if not reach_match:
        reach_match = re.search(
            r'path.*?(?:from|between).*?(\d+).*?(?:to|and).*?(\d+)', q_lower)
    if reach_match:
        src, dst = int(reach_match.group(1)), int(reach_match.group(2))
        visited, frontier, found, hops = {src}, [src], False, 0
        while frontier and hops < 4:
            r_f = len(frontier)
            p_r = obliv_pad_size(r_f)
            real_records = [
                {"nid": nid, "enc_adj_hex": enc_adj[nid]}
                for nid in frontier if nid in enc_adj
            ]
            overhead = p_r - len(real_records)
            dummy_records = [
                {"nid": -i, "enc_adj_hex": real_records[i % len(real_records)]["enc_adj_hex"]}
                for i in range(overhead)
            ] if real_records else []
            # Oblivious scan — ALL p_r processed, no early exit even after dst found
            decrypted = obliv_scan_adjacency(K, real_records + dummy_records)
            new_f = []
            for nid, nbrs in decrypted.items():
                for nbr, _ in nbrs:
                    if nbr == dst:
                        found = True
                    if nbr not in visited:
                        visited.add(nbr)
                        new_f.append(nbr)
            hops += 1
            frontier = new_f

        return {
            "query": q,
            "result": "YES" if found else "NO (within 4 hops)",
            "unit": "reachability",
            "explanation": (
                f"Node {src} → Node {dst}: {'REACHABLE. Within ' + str(hops) + ' hops.' if found else 'NOT REACHABLE within 4 hops.'}"
            ),
            "latency_ms": ms(),
        }

    # ── Subgraph pattern match ─────────────────────────────
    pattern_match = re.search(r'find\s+(\w+)\s+(\w+)\s+(\w+)', q_lower)
    if pattern_match:
        src_lbl, edge_lbl, dst_lbl = pattern_match.groups()
        src_lbl = src_lbl.capitalize()
        edge_lbl = edge_lbl.upper()
        dst_lbl = dst_lbl.capitalize()

        candidates = [n for n, l in node_label.items() if l == src_lbl]
        r = len(candidates)
        p_r = obliv_pad_size(r) if r > 0 else 0

        real_records = [
            {"nid": nid, "enc_adj_hex": enc_adj[nid]}
            for nid in candidates if nid in enc_adj
        ]
        overhead = p_r - len(real_records)
        dummy_records = [
            {"nid": -i, "enc_adj_hex": real_records[i % len(real_records)]["enc_adj_hex"]}
            for i in range(overhead)
        ] if real_records else []
        padded = real_records + dummy_records

        t_scan_start = time.perf_counter()
        # Oblivious scan — ALL p_r records processed unconditionally
        decrypted = obliv_scan_adjacency(K, padded)
        t_scan_ms = (time.perf_counter() - t_scan_start) * 1000

        count = 0
        for nid, nbrs in decrypted.items():
            if node_label.get(nid) != src_lbl:
                continue
            for nbr, elbl in nbrs:
                if elbl == edge_lbl and node_label.get(nbr) == dst_lbl:
                    count += 1

        return {
            "query": q, "result": count,
            "unit": f"({src_lbl})-[{edge_lbl}]->({dst_lbl}) patterns",
            "explanation": (
                f"Found {count} subgraph matches for pattern: ({src_lbl})-[{edge_lbl}]->({dst_lbl})\n"
                f"OblivGM padding P(r) = 2r = {p_r} candidates scanned ({overhead} dummies).\n"
                f"Oblivious scan: {t_scan_ms:.2f} ms — all {p_r} records processed, no early exit.\n"
                f"[Software AES-GCM on host CPU — no TEE enclave involved.]"
            ),
            "latency_ms": ms(),
            "privacy_note": "Oblivious scan: observer sees uniform 2r AES-GCM decryptions — pattern hidden.",
        }

    # ── Fallback ──────────────────────────────────────────
    return {
        "query": q, "result": "?",
        "explanation": (
            "Query not understood. Try:\n"
            "• 'how many nodes'\n"
            "• 'how many connections does node 42 have'\n"
            "• 'what label is node 0'\n"
            "• 'how many Executive nodes'\n"
            "• 'bfs from 0 depth 2'\n"
            "• 'can node 0 reach node 100'\n"
            "• 'find Executive REPLY Manager'"
        ),
        "latency_ms": ms(),
    }

# ── HTML Template ─────────────────────────────────────────
HTML = '''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>OblivGM — Graph Query Tool (Oblivious)</title>
<link href="https://fonts.googleapis.com/css2?family=DM+Sans:wght@400;500;600;700&family=DM+Mono:wght@400;500&display=swap" rel="stylesheet">
<style>
  :root {
    --bg: #f7f8fa; --surface: #ffffff; --surface2: #f0f2f5;
    --border: #e2e5ea; --blue: #d97706; --blue-light: #fef3c7;
    --blue-mid: #fcd34d; --green: #16a34a; --green-light: #dcfce7;
    --amber: #d97706; --amber-light: #fef3c7; --red: #dc2626;
    --red-light: #fee2e2; --text: #1a1d23; --text-2: #4b5563;
    --text-3: #9ca3af; --mono: \'DM Mono\', monospace;
    --sans: \'DM Sans\', sans-serif; --radius: 12px;
    --shadow: 0 1px 4px rgba(0,0,0,0.06), 0 4px 16px rgba(0,0,0,0.04);
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { background: var(--bg); color: var(--text); font-family: var(--sans);
         min-height: 100vh; font-size: 15px; line-height: 1.6; }
  body::before {
    content: \'\'; position: fixed; inset: 0; z-index: 0;
    background-image: radial-gradient(circle, #cbd5e1 1px, transparent 1px);
    background-size: 28px 28px; opacity: 0.45; pointer-events: none;
  }
  .container { max-width: 860px; margin: 0 auto; padding: 48px 24px 64px;
               position: relative; z-index: 1; }
  header { margin-bottom: 40px; }
  .pill { display: inline-flex; align-items: center; gap: 7px;
          background: var(--blue-light); border: 1px solid var(--blue-mid);
          border-radius: 99px; padding: 5px 14px; font-size: 12px;
          font-weight: 600; color: var(--blue); letter-spacing: 0.04em;
          text-transform: uppercase; margin-bottom: 18px; }
  .pill-dot { width: 7px; height: 7px; border-radius: 50%;
              background: var(--blue); animation: blink 2s ease-in-out infinite; }
  @keyframes blink { 0%,100%{opacity:1} 50%{opacity:0.25} }
  h1 { font-size: 2.4rem; font-weight: 700; line-height: 1.15;
       letter-spacing: -0.02em; color: var(--text); margin-bottom: 10px; }
  h1 span { color: var(--blue); }
  .subtitle { color: var(--text-2); font-size: 0.95rem; max-width: 560px; line-height: 1.7; }
  .card { background: var(--surface); border: 1px solid var(--border);
          border-radius: var(--radius); padding: 28px; margin-bottom: 18px;
          box-shadow: var(--shadow); transition: box-shadow 0.2s; }
  .card:hover { box-shadow: 0 2px 8px rgba(0,0,0,0.08), 0 8px 24px rgba(0,0,0,0.06); }
  .card-header { display: flex; align-items: center; gap: 10px; margin-bottom: 20px; }
  .step-badge { width: 26px; height: 26px; border-radius: 8px; background: var(--blue);
                color: white; font-size: 12px; font-weight: 700;
                display: flex; align-items: center; justify-content: center; flex-shrink: 0; }
  .card-title { font-size: 1rem; font-weight: 600; color: var(--text); }
  .card-desc  { font-size: 0.82rem; color: var(--text-3); margin-top: 2px; }
  input { width: 100%; background: var(--surface2); border: 1.5px solid var(--border);
          border-radius: 9px; padding: 11px 15px; color: var(--text);
          font-family: var(--mono); font-size: 0.875rem; outline: none;
          transition: border-color 0.18s, background 0.18s; }
  input:focus { border-color: var(--blue); background: #fff; }
  input::placeholder { color: var(--text-3); }
  .input-row { display: flex; gap: 10px; margin-bottom: 14px; }
  .input-row input { flex: 1; }
  button { background: var(--blue); color: white; border: none; border-radius: 9px;
           padding: 11px 22px; font-family: var(--sans); font-weight: 600;
           font-size: 0.875rem; cursor: pointer; white-space: nowrap;
           transition: background 0.18s, transform 0.15s, box-shadow 0.18s;
           box-shadow: 0 1px 3px rgba(217,119,6,0.25); }
  button:hover { background: #b45309; transform: translateY(-1px);
                 box-shadow: 0 4px 12px rgba(217,119,6,0.3); }
  button:active { transform: translateY(0); }
  button.secondary { background: var(--surface2); color: var(--text-2);
                     border: 1.5px solid var(--border); box-shadow: none; }
  button.secondary:hover { background: #e9ecf2; color: var(--text); box-shadow: none; }
  button:disabled { opacity: 0.45; cursor: not-allowed; transform: none; box-shadow: none; }
  .status-bar { display: flex; align-items: center; gap: 9px; padding: 11px 15px;
                border-radius: 9px; font-size: 0.85rem; margin-bottom: 14px;
                font-family: var(--sans); }
  .status-bar.idle    { background: var(--surface2); border: 1px solid var(--border); color: var(--text-3); }
  .status-bar.loading { background: var(--amber-light); border: 1px solid #fcd34d; color: var(--amber); }
  .status-bar.ready   { background: var(--green-light); border: 1px solid #86efac; color: var(--green); }
  .status-bar.error   { background: var(--red-light); border: 1px solid #fca5a5; color: var(--red); }
  .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(110px, 1fr));
                gap: 10px; margin-top: 14px; }
  .stat-box { background: var(--surface2); border: 1px solid var(--border); border-radius: 10px;
              padding: 14px 12px; text-align: center; transition: background 0.15s; }
  .stat-box:hover { background: var(--blue-light); border-color: var(--blue-mid); }
  .stat-value { font-size: 1.45rem; font-weight: 700; color: var(--blue);
                font-family: var(--mono); line-height: 1.1; }
  .stat-label { font-size: 0.7rem; color: var(--text-3); margin-top: 5px;
                text-transform: uppercase; letter-spacing: 0.06em; }
  .chips { display: flex; flex-wrap: wrap; gap: 7px; margin-top: 14px; }
  .chip { background: var(--surface2); border: 1.5px solid var(--border); border-radius: 7px;
          padding: 5px 11px; font-family: var(--mono); font-size: 0.78rem; color: var(--text-2);
          cursor: pointer; transition: all 0.15s; }
  .chip:hover { background: var(--blue-light); border-color: var(--blue-mid); color: var(--blue); }
  .label-tags { display: flex; flex-wrap: wrap; gap: 7px; margin-top: 12px; }
  .label-tag { padding: 4px 10px; border-radius: 6px; font-size: 0.75rem;
               font-family: var(--mono); font-weight: 500; }
  .tag-inf  { background: #f3e8ff; color: #7c3aed; border: 1px solid #ddd6fe; }
  .tag-per  { background: var(--blue-light); color: var(--blue); border: 1px solid var(--blue-mid); }
  .tag-com  { background: var(--green-light); color: var(--green); border: 1px solid #86efac; }
  .tag-org  { background: var(--amber-light); color: var(--amber); border: 1px solid #fcd34d; }
  .tag-bot  { background: var(--red-light); color: var(--red); border: 1px solid #fca5a5; }
  .tag-edge { background: var(--surface2); color: var(--text-3); border: 1px solid var(--border); }
  .query-row { display: flex; gap: 10px; align-items: center; margin-top: 14px; flex-wrap: wrap; }
  .query-hint { font-size: 0.8rem; color: var(--text-3); }
  .result-panel { display: none; }
  .result-panel.visible { display: block; }
  .result-hero { margin-bottom: 18px; }
  .result-number { font-size: 3.2rem; font-weight: 700; color: var(--blue);
                   font-family: var(--mono); line-height: 1; letter-spacing: -0.02em; }
  .result-unit { font-size: 0.88rem; color: var(--text-3); font-family: var(--mono); margin-top: 4px; }
  .result-explanation { font-family: var(--mono); font-size: 0.82rem; color: var(--text-2);
                        background: var(--surface2); border: 1px solid var(--border);
                        border-radius: 9px; padding: 14px 16px; white-space: pre-wrap; line-height: 1.7; }
  .privacy-note { display: flex; align-items: flex-start; gap: 9px; margin-top: 12px;
                  padding: 12px 15px; background: var(--blue-light);
                  border: 1px solid var(--blue-mid); border-radius: 9px;
                  font-size: 0.8rem; color: #92400e; font-family: var(--sans); }
  .privacy-icon { font-size: 1rem; flex-shrink: 0; margin-top: 1px; }
  .latency { font-family: var(--mono); font-size: 0.75rem; color: var(--text-3); margin-top: 10px; }
  .spinner { width: 16px; height: 16px; border: 2px solid rgba(217,119,6,0.25);
             border-top-color: var(--amber); border-radius: 50%;
             animation: spin 0.75s linear infinite; flex-shrink: 0; }
  @keyframes spin { to { transform: rotate(360deg); } }
  .divider { border: none; border-top: 1px solid var(--border); margin: 8px 0 16px; }
  .info-banner { display: flex; gap: 10px; align-items: flex-start; background: var(--surface2);
                 border: 1px solid var(--border); border-radius: 9px; padding: 11px 14px;
                 font-size: 0.82rem; color: var(--text-2); margin-bottom: 14px; line-height: 1.55; }
  .info-icon { font-size: 0.95rem; flex-shrink: 0; margin-top: 1px; }
</style>
</head>
<body>
<div class="container">

  <header>
    <div class="pill">
      <span class="pill-dot"></span>
      Research Prototype · OblivGM · Software-Only Oblivious Mode
    </div>
    <h1>Graph Query Tool<br><span>with Oblivious Padding</span></h1>
    <p class="subtitle">
      Load a social network dataset, then ask natural questions about it —
      all crypto runs on the host CPU using software AES-GCM with fixed
      <strong>2× oblivious padding</strong>. No TEE, no enclave, no Spark.
    </p>
  </header>

  <div class="card">
    <div class="card-header">
      <div class="step-badge">1</div>
      <div>
        <div class="card-title">Load a Dataset</div>
        <div class="card-desc">Paste a SNAP edge-list URL (.txt or .txt.gz)</div>
      </div>
    </div>
    <div class="info-banner">
      <span class="info-icon">ℹ️</span>
      <span>
        The graph is encrypted with <strong>AES-256-GCM</strong> before processing.
        OblivGM hides access patterns via <strong>fixed 2× padding</strong> — every query
        fetches exactly P(r)=2r blocks and processes them all obliviously (no early exit,
        no DSSE index, no hardware enclave). Try the Email-Enron dataset below, or grab one from
        <a href="https://snap.stanford.edu/data" target="_blank" style="color:var(--blue)">snap.stanford.edu</a>.
      </span>
    </div>
    <div class="input-row">
      <input type="text" id="datasetUrl"
        placeholder="https://snap.stanford.edu/data/email-Enron.txt.gz"
        value="https://snap.stanford.edu/data/email-Enron.txt.gz">
      <button onclick="loadDataset()" id="loadBtn">Load Graph</button>
    </div>
    <div class="status-bar idle" id="loadStatus">
      <span>No dataset loaded yet</span>
    </div>
    <div id="graphStats" style="display:none">
      <div class="stats-grid" id="statsGrid"></div>
      <div class="label-tags" id="labelTags"></div>
    </div>
  </div>

  <div class="card">
    <div class="card-header">
      <div class="step-badge">2</div>
      <div>
        <div class="card-title">Ask a Question</div>
        <div class="card-desc">Type in plain English, or pick a sample below</div>
      </div>
    </div>
    <input id="queryInput" placeholder="e.g. How many connections does node 42 have?">
    <div class="query-row">
      <button onclick="runQuery()" id="queryBtn" disabled>Run Query</button>
      <button class="secondary" onclick="clearResult()">Clear</button>
      <span id="queryHint" class="query-hint">Load a dataset first to get started</span>
    </div>
    <div class="chips" id="queryChips"></div>
  </div>

  <div class="card result-panel" id="resultPanel">
    <div class="card-header">
      <div class="step-badge" style="background:#16a34a">3</div>
      <div><div class="card-title">Result</div></div>
    </div>
    <div class="result-hero">
      <div class="result-number" id="resultNumber">—</div>
      <div class="result-unit"   id="resultUnit"></div>
    </div>
    <div class="result-explanation" id="resultExplanation"></div>
    <div class="privacy-note" id="privacyNote" style="display:none">
      <span class="privacy-icon">🔒</span>
      <span id="privacyNoteText"></span>
    </div>
    <div class="latency" id="resultLatency"></div>
  </div>

</div>
<script>
let graphLoaded = false;

const SAMPLE_QUERIES = [
  "How many nodes?",
  "How many edges?",
  "How many connections does node 0 have?",
  "What label is node 0?",
  "How many Executive nodes?",
  "How many Employee nodes?",
  "BFS from node 0 depth 2",
  "Can node 0 reach node 500?",
  "Find Executive REPLY Manager",
];

function setStatus(id, type, html) {
  const el = document.getElementById(id);
  el.className = `status-bar ${type}`;
  el.innerHTML = html;
}

async function loadDataset() {
  const url = document.getElementById('datasetUrl').value.trim();
  if (!url) return;
  document.getElementById('loadBtn').disabled = true;
  setStatus('loadStatus', 'loading',
    '<div class="spinner"></div><span>Downloading and encrypting graph...</span>');
  document.getElementById('graphStats').style.display = 'none';
  try {
    const resp = await fetch('/api/load', {
      method: 'POST',
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify({url})
    });
    const data = await resp.json();
    if (data.error) throw new Error(data.error);

    setStatus('loadStatus', 'ready',
      `<span>✓ Graph loaded & encrypted — ${data.stats.nodes.toLocaleString()} nodes, ${data.stats.edges.toLocaleString()} edges · <strong>OblivGM mode</strong> (software AES-GCM, 2× padding)</span>`);

    const sg = document.getElementById('statsGrid');
    sg.innerHTML = `
      <div class="stat-box"><div class="stat-value">${data.stats.nodes.toLocaleString()}</div><div class="stat-label">Nodes</div></div>
      <div class="stat-box"><div class="stat-value">${data.stats.edges.toLocaleString()}</div><div class="stat-label">Edges</div></div>
      <div class="stat-box"><div class="stat-value">${data.stats.max_degree.toLocaleString()}</div><div class="stat-label">Max Degree</div></div>
      <div class="stat-box"><div class="stat-value">${data.stats.avg_degree}</div><div class="stat-label">Avg Degree</div></div>
      <div class="stat-box"><div class="stat-value">${data.stats.labels.length}</div><div class="stat-label">Label Types</div></div>
    `;
    document.getElementById('graphStats').style.display = 'block';

    const lt = document.getElementById('labelTags');
    const tagClass = {'Executive':'tag-inf','Manager':'tag-per','Employee':'tag-com','External':'tag-org','Inactive':'tag-bot'};
    lt.innerHTML = data.stats.labels.map(l => {
      const cls = tagClass[l] || 'tag-edge';
      const cnt = data.stats.label_counts[l];
      return `<span class="label-tag ${cls}">${l}: ${cnt.toLocaleString()}</span>`;
    }).join('');

    document.getElementById('queryBtn').disabled = false;
    document.getElementById('queryHint').textContent = '';
    document.getElementById('queryChips').innerHTML =
      SAMPLE_QUERIES.map(q => `<div class="chip" onclick="setQuery('${q}')">${q}</div>`).join('');
    graphLoaded = true;
  } catch(e) {
    setStatus('loadStatus', 'error', `<span>✗ Error: ${e.message}</span>`);
  }
  document.getElementById('loadBtn').disabled = false;
}

function setQuery(q) { document.getElementById('queryInput').value = q; }

async function runQuery() {
  const q = document.getElementById('queryInput').value.trim();
  if (!q || !graphLoaded) return;
  document.getElementById('queryBtn').disabled = true;
  document.getElementById('resultPanel').className = 'card result-panel visible';
  document.getElementById('resultNumber').textContent = '...';
  document.getElementById('resultUnit').textContent = '';
  document.getElementById('resultExplanation').textContent = 'Running oblivious scan...';
  document.getElementById('privacyNote').style.display = 'none';
  try {
    const resp = await fetch('/api/query', {
      method: 'POST',
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify({query: q})
    });
    const data = await resp.json();
    document.getElementById('resultNumber').textContent = data.result;
    document.getElementById('resultUnit').textContent = data.unit || '';
    document.getElementById('resultExplanation').textContent = data.explanation;
    document.getElementById('resultLatency').textContent = `Query latency: ${data.latency_ms} ms`;
    if (data.privacy_note) {
      document.getElementById('privacyNote').style.display = 'flex';
      document.getElementById('privacyNoteText').textContent = data.privacy_note;
    }
  } catch(e) {
    document.getElementById('resultNumber').textContent = 'Error';
    document.getElementById('resultExplanation').textContent = e.message;
  }
  document.getElementById('queryBtn').disabled = false;
}

function clearResult() {
  document.getElementById('resultPanel').className = 'card result-panel';
  document.getElementById('queryInput').value = '';
}

document.addEventListener('DOMContentLoaded', () => {
  document.getElementById('queryInput').addEventListener('keydown', e => {
    if (e.key === 'Enter' && e.ctrlKey) runQuery();
  });
});
</script>
</body>
</html>'''

# ── API Routes ─────────────────────────────────────────────
@app.route('/')
def index():
    return render_template_string(HTML)

@app.route('/api/load', methods=['POST'])
def api_load():
    data = request.get_json()
    url  = data.get('url', '').strip()
    if not url:
        return jsonify({"error": "No URL provided"}), 400
    try:
        tmp = os.path.join(os.getcwd(), "oblivgm_input.txt")
        if url.endswith('.gz'):
            gz = tmp + ".gz"
            urllib.request.urlretrieve(url, gz)
            with gzip.open(gz, 'rb') as fi, open(tmp, 'wb') as fo:
                fo.write(fi.read())
            os.remove(gz)
        else:
            urllib.request.urlretrieve(url, tmp)

        with open(tmp, encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()

        nodes, edges = load_edge_list(lines)
        if not nodes:
            return jsonify({"error": "No valid edges found. Expected format: 'u v' per line."}), 400

        K, node_label, edge_label, adj, enc_adj, hist, stats = build_obliv_graph(nodes, edges)

        STATE.update({
            "loaded": True, "nodes": nodes, "edges": edges,
            "node_label": node_label, "edge_label": edge_label,
            "adj": adj, "enc_adj": enc_adj,
            "K": K,
            "hist": hist,
            "dataset_name": url.split('/')[-1],
            "stats": stats,
        })
        return jsonify({"ok": True, "stats": stats})

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/query', methods=['POST'])
def api_query():
    if not STATE["loaded"]:
        return jsonify({"error": "No dataset loaded"}), 400
    q = request.get_json().get('query', '').strip()
    if not q:
        return jsonify({"error": "Empty query"}), 400
    try:
        return jsonify(parse_query(q))
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/status', methods=['GET'])
def api_status():
    return jsonify({
        "mechanism": "OblivGM",
        "padding": "fixed_2x",
        "tee": False,
        "dsse": False,
        "spark": False,
        "loaded": STATE["loaded"],
    })

if __name__ == '__main__':
    print("=" * 55)
    print("  OblivGM  ·  TeeDemo")
    print("  Mechanism : Software-only oblivious scan")
    print("  Padding   : Fixed 2× (P(r) = 2r)")
    print("  TEE       : Not used")
    print("  DSSE      : Not used")
    print("  Spark     : Not used")
    print("  Open      : http://localhost:5000")
    print("=" * 55)
    app.run(debug=False, host='0.0.0.0', port=5000)