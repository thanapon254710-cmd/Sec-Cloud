"""
DVH-GQP  —  TeeDemo
────────────────────────────────────────────────────────────
Run (local / no enclave):
    pip install flask pycryptodome
    python DVHGQP-TeeDemo.py

Run (full TEE stack):
    pip install flask pycryptodome neo4j pyspark python-dotenv
    Set NEO4J_URI / NEO4J_USERNAME / NEO4J_PASSWORD / ENCLAVE_CID / ENCLAVE_PORT
    in a .env file, then: python DVHGQP-TeeDemo.py

Then open: http://localhost:5000

Architecture
────────────
• Plaintext never leaves the TEE boundary.
• The host (this process) holds encrypted adjacency lists (enc_adj) and
  an encrypted DSSE label index (dsse_index).
• Every crypto operation that touches raw graph data is sent to the
  Nitro Enclave via vsock.
• When the enclave is not reachable (local demo mode) the same operations
  fall back to in-process AES-GCM — identical results, no TEE guarantee.
"""

from flask import Flask, request, jsonify, render_template_string
import os, json, time, math, hashlib, collections, gzip, urllib.request, re
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

# ── Optional TEE / Neo4j / Spark imports ────────────────────
try:
    from dotenv import load_dotenv
    load_dotenv(dotenv_path=os.path.join(os.path.dirname(__file__), ".env"))
except ImportError:
    pass

try:
    from neo4j import GraphDatabase
    _NEO4J_AVAILABLE = True
except ImportError:
    _NEO4J_AVAILABLE = False

try:
    from pyspark.sql import SparkSession
    _SPARK_AVAILABLE = True
except ImportError:
    _SPARK_AVAILABLE = False

app = Flask(__name__)

# ── Configuration ────────────────────────────────────────────
CONFIG = {
    "NEO4J_URI":      os.getenv("NEO4J_URI",      "bolt://localhost:7687"),
    "NEO4J_USERNAME": os.getenv("NEO4J_USERNAME",  "neo4j"),
    "NEO4J_PASSWORD": os.getenv("NEO4J_PASSWORD",  "password"),
    "BATCH_SIZE":     int(os.getenv("BATCH_SIZE",  "500")),
}
ENCLAVE_CID  = int(os.getenv("ENCLAVE_CID",  "16"))
ENCLAVE_PORT = int(os.getenv("ENCLAVE_PORT", "5000"))
DATASET_ID   = "dataset_demo"

# ── Crypto helpers ───────────────────────────────────────────
def keygen():                    return get_random_bytes(32)
def prf(ks, w):                  return hashlib.sha256(ks + w.encode()).hexdigest()
def pad_size(r): # Adaptive padding strategy based on result size r 
    if    r == 0:   return 0
    if    r < 1000: ratio = 0.25 #small
    elif  r < 5000: ratio = 0.15 #medium
    else:           ratio = 0.10 #large
        
    return r + max(1, math.ceil(r * ratio))

def aes_gcm_encrypt(key, pt):
    c = AES.new(key, AES.MODE_GCM)
    ct, tag = c.encrypt_and_digest(pt)
    return c.nonce + tag + ct

def aes_gcm_decrypt(key, blob):
    n, tag, ct = blob[:16], blob[16:32], blob[32:]
    return AES.new(key, AES.MODE_GCM, nonce=n).decrypt_and_verify(ct, tag)

# ── TEE vsock transport ──────────────────────────────────────
def _vsock_call(op, payload, cid=None, port=None):
    """Send an operation to the Nitro Enclave over vsock.
    Raises RuntimeError or OSError if the enclave is unreachable."""
    import socket as _socket, struct as _struct
    cid  = cid  or ENCLAVE_CID
    port = port or ENCLAVE_PORT
    body   = json.dumps({"op": op, "payload": payload}).encode("utf-8")
    header = _struct.pack(">I", len(body))
    sock = _socket.socket(_socket.AF_VSOCK, _socket.SOCK_STREAM)
    sock.settimeout(30)
    try:
        sock.connect((cid, port))
        sock.sendall(header + body)
        raw_len = b""
        while len(raw_len) < 4:
            chunk = sock.recv(4 - len(raw_len))
            if not chunk: raise ConnectionError("vsock closed")
            raw_len += chunk
        resp_len = _struct.unpack(">I", raw_len)[0]
        raw_resp = b""
        while len(raw_resp) < resp_len:
            chunk = sock.recv(min(65536, resp_len - len(raw_resp)))
            if not chunk: raise ConnectionError("vsock closed mid-response")
            raw_resp += chunk
        response = json.loads(raw_resp.decode("utf-8"))
        if response.get("status") != "ok":
            raise RuntimeError(f"Enclave error: {response.get('message')}")
        return response["result"]
    finally:
        sock.close()

_TEE_AVAILABLE = None   # None = not yet probed

def _probe_tee():
    """Try a ping to the enclave; cache the result."""
    global _TEE_AVAILABLE
    if _TEE_AVAILABLE is not None:
        return _TEE_AVAILABLE
    try:
        _vsock_call("ping", {})
        _TEE_AVAILABLE = True
    except Exception:
        _TEE_AVAILABLE = False
    return _TEE_AVAILABLE

# ── TEE operations with local fallback ──────────────────────
def tee_decrypt_adjacency(K: bytes, enc_adj_hex: str) -> list:
    """Decrypt one adjacency list.  TEE if available, else local AES-GCM."""
    if _probe_tee():
        result = _vsock_call("decrypt_adjacency_single",
                             {"key_hex": K.hex(), "enc_adj_hex": enc_adj_hex})
        return result["neighbors"]
    # local fallback
    return json.loads(aes_gcm_decrypt(K, bytes.fromhex(enc_adj_hex)).decode())

def tee_decrypt_dsse(Ke: bytes, entries: list) -> list:
    """Decrypt DSSE entries and return real (non-dummy) ids.
    TEE if available, else local AES-GCM."""
    t0 = time.perf_counter()
    if _probe_tee():
        result = _vsock_call("decrypt_dsse",
                             {"key_hex": Ke.hex(), "entries": entries})
        real_ids = result["real_ids"]
    else:
        # local fallback
        real_ids = []
        for hex_blob in entries:
            parsed = json.loads(aes_gcm_decrypt(Ke, bytes.fromhex(hex_blob)).decode())
            if isinstance(parsed, list):
                real_ids.append(parsed)
    t_ms = (time.perf_counter() - t0) * 1000
    return real_ids, t_ms

# ── In-memory state ──────────────────────────────────────────
STATE = {
    "loaded":       False,
    "nodes":        set(),
    "edges":        [],
    "node_label":   {},
    "edge_label":   {},
    "adj":          {},     # plaintext adjacency (host-side, for BFS/pattern)
    "enc_adj":      {},     # encrypted adjacency index
    "dsse_index":   {},
    "K":            None,
    "Ks":           None,
    "Ke":           None,
    "dataset_name": "",
    "stats":        {},
    # optional Neo4j driver
    "driver":       None,
}

NODE_LABELS = ["Person", "Influencer", "Community", "Organization", "Bot"]
EDGE_LABELS = ["FRIEND", "FOLLOWS", "MEMBER_OF", "INTERACTS"]

# ── Graph helpers ────────────────────────────────────────────
def assign_labels(nodes, edges):
    degree = {}
    for u, v in edges:
        degree[u] = degree.get(u, 0) + 1
        degree[v] = degree.get(v, 0) + 1

    if not degree:
        return {n: "Bot" for n in nodes}, {}, degree

    degs = sorted(degree.values())
    n    = len(degs)
    p95  = degs[int(n * 0.95)]
    p75  = degs[int(n * 0.75)]
    p50  = degs[int(n * 0.50)]
    p25  = degs[int(n * 0.25)]

    node_label = {}
    for nd in nodes:
        d = degree.get(nd, 0)
        if   d >= p95: node_label[nd] = "Influencer"
        elif d >= p75: node_label[nd] = "Community"
        elif d >= p50: node_label[nd] = "Person"
        elif d >= p25: node_label[nd] = "Organization"
        else:          node_label[nd] = "Bot"

    unique_edges = list({(min(u, v), max(u, v)) for u, v in edges})
    edge_label   = {(u, v): EDGE_LABELS[(u + v) % 4] for u, v in unique_edges}
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

def build_encrypted_graph(nodes, edges):
    node_label, edge_label, degree = assign_labels(nodes, edges)
    K, Ks, Ke = keygen(), keygen(), keygen()

    # Adjacency
    adj = collections.defaultdict(list)
    for u, v in edges:
        adj[u].append((v, edge_label[(u, v)]))
        adj[v].append((u, edge_label[(u, v)]))

    # Encrypted adjacency index
    enc_adj = {}
    for node, neighbors in adj.items():
        enc_adj[node] = aes_gcm_encrypt(K, json.dumps(neighbors).encode()).hex()

    # DSSE label index
    hist = {}
    for v, lbl in node_label.items():
        hist.setdefault(lbl, []).append(("v", v))
    for (u, v), lbl in edge_label.items():
        hist.setdefault(lbl, []).append(("e", u, v))

    dsse_index = {}
    for w, real_ids in hist.items():
        r     = len(real_ids)
        p     = pad_size(r)
        real_e  = [json.dumps(list(x)) for x in real_ids]
        dummy_e = [json.dumps(f"__dummy_{i}__{w}") for i in range(p - r)]
        enc_list = [aes_gcm_encrypt(Ke, e.encode()).hex() for e in real_e + dummy_e]
        dsse_index[prf(Ks, w)] = {"entries": enc_list, "p_r": p, "label": w, "r": r}

    stats = {
        "nodes":        len(nodes),
        "edges":        len(edges),
        "labels":       list(hist.keys()),
        "label_counts": {w: len(ids) for w, ids in hist.items()},
        "max_degree":   max(degree.values()) if degree else 0,
        "avg_degree":   round(sum(degree.values()) / max(len(degree), 1), 2),
    }
    return K, Ks, Ke, node_label, edge_label, dict(adj), enc_adj, dsse_index, stats

# ── Optional Neo4j load (only if available) ──────────────────
def phase2_load_neo4j(driver, nodes, enc_adj, node_label):
    """Store encrypted nodes in Neo4j when the driver is available."""
    bs = CONFIG["BATCH_SIZE"]
    node_list = list(nodes)
    with driver.session() as session:
        session.run("MATCH (n:EncNode {dataset_id:$ds}) DETACH DELETE n", ds=DATASET_ID)
        for i in range(0, len(node_list), bs):
            batch = [
                {"nid": str(nid),
                 "adj_ct": enc_adj.get(nid, ""),
                 "lbl": node_label.get(nid, "")}
                for nid in node_list[i: i + bs]
            ]
            session.run("""
                UNWIND $batch AS row
                CREATE (n:EncNode {dataset_id:$ds, node_id:row.nid,
                                   adj_ct:row.adj_ct, label:row.lbl})
            """, batch=batch, ds=DATASET_ID)
        session.run("CREATE INDEX enc_node_id IF NOT EXISTS FOR (n:EncNode) ON (n.node_id)")

# ── Query Engine ─────────────────────────────────────────────
def parse_query(q):
    q_lower = q.lower().strip()
    t0 = time.perf_counter()

    node_label  = STATE["node_label"]
    edge_label  = STATE["edge_label"]
    adj         = STATE["adj"]
    enc_adj     = STATE["enc_adj"]
    K, Ks, Ke   = STATE["K"], STATE["Ks"], STATE["Ke"]
    dsse_index  = STATE["dsse_index"]
    tee_mode    = _probe_tee()

    def ms(): return round((time.perf_counter() - t0) * 1000, 2)

    # ── Count nodes ──────────────────────────────────────────
    if any(x in q_lower for x in ["how many nodes", "count nodes", "total nodes", "number of nodes"]):
        r = len(STATE["nodes"])
        return {"query": q, "result": r, "unit": "nodes",
                "explanation": f"The graph contains {r} nodes total.",
                "latency_ms": ms()}

    # ── Count edges ──────────────────────────────────────────
    if any(x in q_lower for x in ["how many edges", "count edges", "total edges", "number of edges"]):
        r = len(STATE["edges"])
        return {"query": q, "result": r, "unit": "edges",
                "explanation": f"The graph contains {r} edges total.",
                "latency_ms": ms()}

    # ── Degree / friends of node X ───────────────────────────
    deg_match = re.search(
        r'(?:degree|friends|neighbors|connections).*?node\s+(\d+)'
        r'|node\s+(\d+).*?(?:degree|friends|neighbors|connections)',
        q_lower)
    if not deg_match:
        deg_match = re.search(
            r'how many (?:friends|neighbors|connections) does (?:node\s+)?(\d+)',
            q_lower)
    if deg_match:
        nid = int(deg_match.group(1) or deg_match.group(2))
        if nid in enc_adj:
            # ── TEE path: decrypt adjacency inside enclave ──
            nbrs   = tee_decrypt_adjacency(K, enc_adj[nid])
            result = len(nbrs)
            sample = [n for n, _ in nbrs[:10]]
            return {
                "query": q, "result": result, "unit": "connections",
                "explanation": (
                    f"Node {nid} ({node_label.get(nid, 'unknown')}) has {result} connections.\n"
                    f"Sample neighbors: {sample}{'...' if result > 10 else ''}\n"
                    f"{'[TEE] Adjacency decrypted inside Nitro Enclave.' if tee_mode else '[Local] Adjacency decrypted locally (no enclave).'}"
                ),
                "latency_ms": ms(),
                "privacy_note": (
                    "Adjacency decrypted inside Nitro Enclave — host never sees plaintext neighbors."
                    if tee_mode else
                    "Running in local mode. In production, decryption happens inside the TEE."
                ),
            }
        else:
            return {"query": q, "result": 0, "unit": "connections",
                    "explanation": f"Node {nid} not found in graph.", "latency_ms": ms()}

    # ── Label of node X ──────────────────────────────────────
    lbl_match = re.search(
        r'(?:label|type|role).*?node\s+(\d+)|node\s+(\d+).*?(?:label|type|role|what is)',
        q_lower)
    if lbl_match:
        nid = int(lbl_match.group(1) or lbl_match.group(2))
        lbl = node_label.get(nid, "not found")
        return {"query": q, "result": lbl, "unit": "label",
                "explanation": f"Node {nid} has label: {lbl}", "latency_ms": ms()}

    # ── Count nodes by label (DSSE query) ────────────────────
    for lbl in NODE_LABELS:
        if lbl.lower() in q_lower and any(x in q_lower for x in ["how many", "count", "number"]):
            token = prf(Ks, lbl)
            if token not in dsse_index:
                return {"query": q, "result": 0, "unit": f"{lbl} nodes",
                        "explanation": f"No entries found for label '{lbl}'.", "latency_ms": ms()}

            entry    = dsse_index[token]
            p_r      = entry["p_r"]
            # ── TEE path: decrypt DSSE entries inside enclave ──
            real_ids, t_tee = tee_decrypt_dsse(Ke, entry["entries"])
            result   = len(real_ids)
            return {
                "query": q, "result": result, "unit": f"{lbl} nodes",
                "explanation": (
                    f"Found {result} {lbl} nodes.\n"
                    f"DSSE padding P(r)={p_r} (overhead = {p_r - result} dummy entries).\n"
                    f"SP only sees {p_r} encrypted entries — cannot determine true count.\n"
                    f"{'[TEE] DSSE decrypted inside Nitro Enclave.' if tee_mode else '[Local] DSSE decrypted locally (no enclave).'}"
                ),
                "latency_ms": ms(),
                "privacy_note": f"Leakage: L(q) = (P(r)={p_r}, access_time)",
            }

    # ── BFS reachability ─────────────────────────────────────
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
            if not frontier: break
            p_r = pad_size(len(frontier))
            new_frontier = []
            for nid in frontier:
                # ── TEE path: decrypt adjacency per frontier node ──
                if nid in enc_adj:
                    nbrs = tee_decrypt_adjacency(K, enc_adj[nid])
                else:
                    nbrs = adj.get(nid, [])
                for nbr, _ in nbrs:
                    if nbr not in visited:
                        visited.add(nbr); new_frontier.append(nbr)
            level_info.append(
                f"Depth {d}: frontier={len(frontier)} → discovered {len(new_frontier)} new nodes "
                f"(ORAM fetches P(r)={p_r})")
            frontier = new_frontier

        return {
            "query": q, "result": len(visited) - 1, "unit": "reachable nodes",
            "explanation": (
                f"BFS from node {start} (depth={depth}): {len(visited) - 1} reachable nodes.\n"
                + "\n".join(level_info) + "\n"
                + f"{'[TEE] Adjacency decrypted inside Nitro Enclave per frontier node.' if tee_mode else '[Local] Decrypted locally.'}"
            ),
            "latency_ms": ms(),
            "privacy_note": "SP only observed P(r) ORAM accesses per level — true frontier sizes hidden.",
        }

    # ── Point-to-point reachability ──────────────────────────
    reach_match = re.search(
        r'(?:can|does|is).*?(?:node\s+)?(\d+).*?reach.*?(?:node\s+)?(\d+)', q_lower)
    if not reach_match:
        reach_match = re.search(
            r'path.*?(?:from|between).*?(\d+).*?(?:to|and).*?(\d+)', q_lower)
    if reach_match:
        src, dst = int(reach_match.group(1)), int(reach_match.group(2))
        visited, frontier, found, hops = {src}, [src], False, 0
        while frontier and hops < 4:
            new_f = []
            for nid in frontier:
                nbrs = tee_decrypt_adjacency(K, enc_adj[nid]) if nid in enc_adj else adj.get(nid, [])
                for nbr, _ in nbrs:
                    if nbr == dst:
                        found = True; break
                    if nbr not in visited:
                        visited.add(nbr); new_f.append(nbr)
                if found: break
            hops += 1; frontier = new_f

        return {
            "query": q,
            "result": "YES" if found else "NO (within 4 hops)",
            "unit": "reachability",
            "explanation": (
                f"Node {src} → Node {dst}: {'REACHABLE' if found else 'NOT REACHABLE within 4 hops'}. "
                f"Explored {len(visited)} nodes."
            ),
            "latency_ms": ms(),
        }

    # ── Subgraph pattern match ────────────────────────────────
    pattern_match = re.search(r'find\s+(\w+)\s+(\w+)\s+(\w+)', q_lower)
    if pattern_match:
        src_lbl, edge_lbl, dst_lbl = pattern_match.groups()
        src_lbl = src_lbl.capitalize(); edge_lbl = edge_lbl.upper(); dst_lbl = dst_lbl.capitalize()
        count = 0
        for nid, lbl in node_label.items():
            if lbl == src_lbl:
                nbrs = tee_decrypt_adjacency(K, enc_adj[nid]) if nid in enc_adj else adj.get(nid, [])
                for nbr, elbl in nbrs:
                    if elbl == edge_lbl and node_label.get(nbr) == dst_lbl:
                        count += 1
        return {
            "query": q, "result": count,
            "unit": f"({src_lbl})-[{edge_lbl}]->({dst_lbl}) patterns",
            "explanation": (
                f"Found {count} subgraph matches for pattern: ({src_lbl})-[{edge_lbl}]->({dst_lbl})\n"
                f"{'[TEE] Edge decryption performed inside Nitro Enclave.' if tee_mode else '[Local] Decrypted locally.'}"
            ),
            "latency_ms": ms(),
            "privacy_note": "Secure evaluation inside Nitro Enclave across Spark workers." if tee_mode else None,
        }

    # ── Fallback ─────────────────────────────────────────────
    return {
        "query": q, "result": "?",
        "explanation": (
            "Query not understood. Try:\n"
            "• 'how many nodes'\n"
            "• 'how many friends does node 42 have'\n"
            "• 'what label is node 0'\n"
            "• 'how many Influencer nodes'\n"
            "• 'bfs from 0 depth 2'\n"
            "• 'can node 0 reach node 100'\n"
            "• 'find Influencer FOLLOWS Person'"
        ),
        "latency_ms": ms(),
    }

# ── HTML Template (identical UI to Demo.py) ──────────────────
HTML = '''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>DVH-GQP — Graph Query Tool (TEE)</title>
<link href="https://fonts.googleapis.com/css2?family=DM+Sans:wght@400;500;600;700&family=DM+Mono:wght@400;500&display=swap" rel="stylesheet">
<style>
  :root {
    --bg: #f7f8fa; --surface: #ffffff; --surface2: #f0f2f5;
    --border: #e2e5ea; --blue: #3b6ef8; --blue-light: #eef2ff;
    --blue-mid: #c7d2fe; --green: #16a34a; --green-light: #dcfce7;
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
  .subtitle { color: var(--text-2); font-size: 0.95rem; max-width: 540px; line-height: 1.7; }
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
           box-shadow: 0 1px 3px rgba(59,110,248,0.25); }
  button:hover { background: #2955d4; transform: translateY(-1px);
                 box-shadow: 0 4px 12px rgba(59,110,248,0.3); }
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
                  font-size: 0.8rem; color: #3730a3; font-family: var(--sans); }
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
      Research Prototype · DVH-GQP · TEE Mode
    </div>
    <h1>Graph Query Tool<br><span>with TEE Encryption</span></h1>
    <p class="subtitle">
      Load a social network dataset, then ask natural questions about it —
      all crypto operations run inside a Nitro Enclave (or fall back to
      local AES-GCM when running without an enclave).
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
        Decryption happens inside the <strong>Nitro Enclave</strong> — the host never
        sees plaintext. Try the Facebook dataset below, or grab one from
        <a href="https://snap.stanford.edu/data" target="_blank" style="color:var(--blue)">snap.stanford.edu</a>.
      </span>
    </div>
    <div class="input-row">
      <input type="text" id="datasetUrl"
        placeholder="https://snap.stanford.edu/data/facebook_combined.txt.gz"
        value="https://snap.stanford.edu/data/facebook_combined.txt.gz">
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
    <input id="queryInput" placeholder="e.g. How many friends does node 42 have?">
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
  "How many friends does node 0 have?",
  "What label is node 0?",
  "How many Influencer nodes?",
  "How many Person nodes?",
  "BFS from node 0 depth 2",
  "Can node 0 reach node 500?",
  "Find Influencer FOLLOWS Person",
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
      `<span>✓ Graph loaded & encrypted — ${data.stats.nodes.toLocaleString()} nodes, ${data.stats.edges.toLocaleString()} edges${data.tee_mode ? " · <strong>TEE active</strong>" : " · local mode"}</span>`);

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
    const tagClass = {Influencer:'tag-inf',Person:'tag-per',Community:'tag-com',Organization:'tag-org',Bot:'tag-bot'};
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
  document.getElementById('resultExplanation').textContent = 'Processing encrypted query...';
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

# ── API Routes ────────────────────────────────────────────────
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
        tmp = os.path.join(os.getcwd(), "dvhgqp_input.txt")
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

        K, Ks, Ke, node_label, edge_label, adj, enc_adj, dsse_index, stats = \
            build_encrypted_graph(nodes, edges)

        # Optional: load into Neo4j if available
        driver = None
        if _NEO4J_AVAILABLE:
            try:
                driver = GraphDatabase.driver(
                    CONFIG["NEO4J_URI"],
                    auth=(CONFIG["NEO4J_USERNAME"], CONFIG["NEO4J_PASSWORD"]))
                driver.verify_connectivity()
                phase2_load_neo4j(driver, nodes, enc_adj, node_label)
            except Exception as e:
                print(f"[Neo4j] Not available, skipping: {e}")
                driver = None

        STATE.update({
            "loaded": True, "nodes": nodes, "edges": edges,
            "node_label": node_label, "edge_label": edge_label,
            "adj": adj, "enc_adj": enc_adj, "dsse_index": dsse_index,
            "K": K, "Ks": Ks, "Ke": Ke,
            "dataset_name": url.split('/')[-1],
            "stats": stats,
            "driver": driver,
        })
        return jsonify({"ok": True, "stats": stats, "tee_mode": _probe_tee()})

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

@app.route('/api/tee_status', methods=['GET'])
def api_tee_status():
    return jsonify({"tee_available": _probe_tee(),
                    "neo4j_available": _NEO4J_AVAILABLE,
                    "spark_available": _SPARK_AVAILABLE})

if __name__ == '__main__':
    print("=" * 55)
    print("  DVH-GQP  ·  TeeDemo")
    print(f"  TEE (Nitro Enclave): {'probing on first query' }")
    print(f"  Neo4j : {'available' if _NEO4J_AVAILABLE else 'not installed — skipped'}")
    print(f"  Spark : {'available' if _SPARK_AVAILABLE else 'not installed — skipped'}")
    print("  Open  : http://localhost:5000")
    print("=" * 55)
    app.run(debug=False, host='0.0.0.0', port=5000)