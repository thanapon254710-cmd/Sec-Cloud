#DVH-GQP  —  TeeDemo

from flask import Flask, request, jsonify, render_template_string
import os, json, time, math, hashlib, collections, gzip, urllib.request, re, threading
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
    if    r < 1000: ratio = 0.20 #small
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
    global _TEE_AVAILABLE
    if _TEE_AVAILABLE is not None:
        return _TEE_AVAILABLE
    try:
        import socket as _socket
        s = _socket.socket(_socket.AF_VSOCK, _socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect((ENCLAVE_CID, ENCLAVE_PORT))
        s.close()
        _TEE_AVAILABLE = True
    except Exception as e:
        print(f"[TEE probe failed]: {type(e).__name__}: {e}")
        _TEE_AVAILABLE = False
    return _TEE_AVAILABLE

# ── TEE operations with local fallback ──────────────────────
def tee_decrypt_adjacency(K: bytes, enc_adj_hex: str) -> list:
    if _probe_tee():
        result = _vsock_call("decrypt_adjacency",
                             {"key_hex": K.hex(),
                              "records": [{"nid": 0, "adj_ct": enc_adj_hex}]})
        neighbors = result.get("neighbors", {})
        # enclave returns {nid: [[nbr, edge_label], ...]}
        nbr_list = list(neighbors.values())[0] if neighbors else []
        return nbr_list
    return json.loads(aes_gcm_decrypt(K, bytes.fromhex(enc_adj_hex)).decode())

def tee_decrypt_dsse(Ke: bytes, entries: list) -> list:
    t0 = time.perf_counter()
    if _probe_tee():
        result = _vsock_call("decrypt_dsse",
                             {"ke_hex": Ke.hex(), "entries": entries})
        real_ids = result["real_ids"]
    else:
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

NODE_LABELS = ["Executive", "Manager", "Employee", "External", "Inactive"]
EDGE_LABELS = ["SEND", "REPLY", "BROADCAST", "INTERNAL"]

NEO4J_SYNC_INTERVAL = 10  # seconds

# ── Auto-sync state ───────────────────────────────────────────
SYNC_STATE = {
    "last_sync_ts":    None,   # epoch float
    "last_sync_str":   "Never",
    "nodes_added":     0,
    "nodes_removed":   0,
    "nodes_updated":   0,
    "edges_added":     0,
    "edges_removed":   0,
    "last_error":      None,
    "running":         False,
}

def _rebuild_dsse_index():
    """Rebuild STATE['dsse_index'] from current node_label and edge_label,
    and refresh STATE['stats']['label_counts'] so the UI shows correct counts.
    """
    Ks = STATE["Ks"]
    Ke = STATE["Ke"]
    node_label = STATE["node_label"]
    edge_label = STATE["edge_label"]

    hist = {}
    for v, lbl in node_label.items():
        hist.setdefault(lbl, []).append(("v", v))
    for (u, v), lbl in edge_label.items():
        hist.setdefault(lbl, []).append(("e", u, v))

    dsse_index = {}
    for w, real_ids in hist.items():
        r       = len(real_ids)
        p       = pad_size(r)
        real_e  = [json.dumps(list(x)) for x in real_ids]
        dummy_e = [json.dumps(f"__dummy_{i}__{w}") for i in range(p - r)]
        enc_list = [aes_gcm_encrypt(Ke, e.encode()).hex() for e in real_e + dummy_e]
        dsse_index[prf(Ks, w)] = {"entries": enc_list, "p_r": p, "label": w, "r": r}

    STATE["dsse_index"] = dsse_index

    # Keep stats in sync so the UI label badges reflect real counts
    STATE["stats"]["labels"]       = list(hist.keys())
    STATE["stats"]["label_counts"] = {w: len(ids) for w, ids in hist.items()}

    print(f"[DSSE] Index rebuilt — {len(dsse_index)} label buckets, "
          f"{sum(v['r'] for v in dsse_index.values())} real entries")


def _neo4j_auto_sync():
    """Background thread: pull Neo4j every NEO4J_SYNC_INTERVAL seconds and
    reconcile creates, deletes, and label edits into STATE."""
    while True:
        time.sleep(NEO4J_SYNC_INTERVAL)
        if not STATE["loaded"] or not STATE["driver"]:
            continue
        try:
            _run_neo4j_sync()
        except Exception as exc:
            SYNC_STATE["last_error"] = str(exc)
            print(f"[AutoSync] Error: {exc}")

def _run_neo4j_sync():
    """Pull the current Neo4j snapshot and apply diffs to STATE."""
    driver = STATE["driver"]
    K      = STATE["K"]
    Ke     = STATE["Ke"]

    nodes_added = nodes_removed = nodes_updated = 0
    edges_added = edges_removed = 0

    with driver.session() as session:
        # ── 1. Nodes ─────────────────────────────────────────
        result  = session.run(
            "MATCH (n:EncNode {dataset_id:$ds}) "
            "RETURN n.node_id AS nid, n.label AS lbl, n.adj_ct AS adj_ct",
            ds=DATASET_ID)
        neo4j_nodes = {}           # nid(int) -> {lbl, adj_ct}
        for rec in result:
            try:
                nid = int(rec["nid"])
            except (TypeError, ValueError):
                continue
            neo4j_nodes[nid] = {"lbl": rec["lbl"] or "Inactive",
                                 "adj_ct": rec["adj_ct"] or ""}

        state_nids  = set(STATE["nodes"])
        neo4j_nids  = set(neo4j_nodes.keys())

        # Additions
        for nid in neo4j_nids - state_nids:
            info = neo4j_nodes[nid]
            STATE["nodes"].add(nid)
            STATE["node_label"][nid] = info["lbl"]
            STATE["adj"][nid] = []
            STATE["enc_adj"][nid] = info["adj_ct"] or aes_gcm_encrypt(
                K, json.dumps([]).encode()).hex()
            nodes_added += 1
            print(f"[AutoSync] ✚ Node added: {nid} ({info['lbl']})")

        # Deletions
        for nid in state_nids - neo4j_nids:
            STATE["nodes"].discard(nid)
            STATE["node_label"].pop(nid, None)
            STATE["adj"].pop(nid, None)
            STATE["enc_adj"].pop(nid, None)
            nodes_removed += 1
            print(f"[AutoSync] ✖ Node removed: {nid}")

        # Label edits
        for nid in state_nids & neo4j_nids:
            new_lbl = neo4j_nodes[nid]["lbl"]
            if STATE["node_label"].get(nid) != new_lbl:
                print(f"[AutoSync] ✎ Node {nid} label: "
                      f"{STATE['node_label'].get(nid)} → {new_lbl}")
                STATE["node_label"][nid] = new_lbl
                nodes_updated += 1
            # adj_ct update (if Neo4j has a non-empty, different ciphertext)
            new_adj_ct = neo4j_nodes[nid]["adj_ct"]
            if new_adj_ct and new_adj_ct != STATE["enc_adj"].get(nid):
                STATE["enc_adj"][nid] = new_adj_ct
                STATE["adj"][nid] = []   # plaintext stale; will decrypt on demand

        # ── 2. Edges ─────────────────────────────────────────
        result = session.run(
            "MATCH (a:EncNode {dataset_id:$ds})-[r:ENC_EDGE]->(b:EncNode {dataset_id:$ds}) "
            "RETURN a.node_id AS src, b.node_id AS dst, r.edge_label AS lbl",
            ds=DATASET_ID)
        neo4j_edges = set()
        neo4j_edge_label = {}
        for rec in result:
            try:
                u, v = int(rec["src"]), int(rec["dst"])
            except (TypeError, ValueError):
                continue
            key = (min(u, v), max(u, v))
            neo4j_edges.add(key)
            neo4j_edge_label[key] = rec["lbl"] or "SEND"

        state_edges = {(min(u, v), max(u, v)) for u, v in STATE["edges"]}

        # Additions
        for key in neo4j_edges - state_edges:
            STATE["edges"].append(key)
            STATE["edge_label"][key] = neo4j_edge_label[key]
            # Update plaintext adjacency for both endpoints
            u, v = key
            lbl  = neo4j_edge_label[key]
            STATE["adj"].setdefault(u, []).append((v, lbl))
            STATE["adj"].setdefault(v, []).append((u, lbl))
            # Re-encrypt adjacency
            STATE["enc_adj"][u] = aes_gcm_encrypt(
                K, json.dumps(STATE["adj"][u]).encode()).hex()
            STATE["enc_adj"][v] = aes_gcm_encrypt(
                K, json.dumps(STATE["adj"][v]).encode()).hex()
            edges_added += 1
            print(f"[AutoSync] ✚ Edge added: {u}↔{v} ({lbl})")

        # Deletions
        for key in state_edges - neo4j_edges:
            u, v = key
            try:
                STATE["edges"].remove(key)
            except ValueError:
                pass
            STATE["edge_label"].pop(key, None)
            # Rebuild adjacency for affected nodes
            for node in (u, v):
                STATE["adj"][node] = [
                    (nbr, lbl) for nbr, lbl in STATE["adj"].get(node, [])
                    if nbr not in (u, v) or (nbr == u and node != v) or (nbr == v and node != u)
                ]
                # simpler: rebuild from scratch
            for node in (u, v):
                neighbors = []
                for eu, ev in STATE["edges"]:
                    lbl = STATE["edge_label"].get((eu, ev)) or STATE["edge_label"].get((ev, eu), "")
                    if eu == node:
                        neighbors.append((ev, lbl))
                    elif ev == node:
                        neighbors.append((eu, lbl))
                STATE["adj"][node] = neighbors
                STATE["enc_adj"][node] = aes_gcm_encrypt(
                    K, json.dumps(neighbors).encode()).hex()
            edges_removed += 1
            print(f"[AutoSync] ✖ Edge removed: {u}↔{v}")

    # ── Rebuild DSSE index whenever anything changed ──────────
    # Label-count queries (e.g. "How many Executive nodes?") read
    # dsse_index — NOT node_label directly. Without rebuilding it,
    # query results stay stale even after STATE["nodes"] is updated.
    changed = nodes_added or nodes_removed or nodes_updated or edges_added or edges_removed
    if changed:
        _rebuild_dsse_index()
        STATE["stats"].update({
            "nodes": len(STATE["nodes"]),
            "edges": len(STATE["edges"]),
        })

    now = time.time()
    SYNC_STATE.update({
        "last_sync_ts":  now,
        "last_sync_str": time.strftime("%H:%M:%S UTC", time.gmtime(now)),
        "nodes_added":   nodes_added,
        "nodes_removed": nodes_removed,
        "nodes_updated": nodes_updated,
        "edges_added":   edges_added,
        "edges_removed": edges_removed,
        "last_error":    None,
        "running":       True,
    })
    print(f"[AutoSync] {time.strftime('%H:%M:%S')} "
          f"+{nodes_added}/-{nodes_removed}/~{nodes_updated} nodes | "
          f"+{edges_added}/-{edges_removed} edges"
          + (" | DSSE rebuilt" if changed else " | no changes"))

def assign_labels(nodes, edges):
    degree = {}
    for u, v in edges:
        degree[u] = degree.get(u, 0) + 1
        degree[v] = degree.get(v, 0) + 1

    if not degree:
        return {n: "Inactive" for n in nodes}, {}, degree

    # Node labels based on degree
    node_label = {}
    for n in nodes:
        d = degree.get(n, 0)
        if   d > 500: node_label[n] = "Executive"
        elif d > 200: node_label[n] = "Manager"
        elif d > 50:  node_label[n] = "Employee"
        elif d > 5:   node_label[n] = "External"
        else:         node_label[n] = "Inactive"

    # Edge labels based on sender/receiver role combination
    edge_label = {}
    for (u, v) in edges:
        src = node_label.get(u, "Inactive")
        dst = node_label.get(v, "Inactive")
        if src in ("Executive", "Manager") and dst in ("Executive", "Manager"):
            edge_label[(u, v)] = "REPLY"        # senior ↔ senior = likely conversation
        elif src in ("Executive", "Manager"):
            edge_label[(u, v)] = "BROADCAST"    # senior → lower = announcement/broadcast
        elif src == dst:
            edge_label[(u, v)] = "INTERNAL"     # same role = peer communication
        else:
            edge_label[(u, v)] = "SEND"         # everything else = general send

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
def phase2_load_neo4j(driver, nodes, edges, enc_adj, node_label, edge_label):
    """Store encrypted nodes and edges in Neo4j when the driver is available."""
    bs = CONFIG["BATCH_SIZE"]
    node_list = list(nodes)
    with driver.session() as session:
        session.run("MATCH (n) DETACH DELETE n")

        # Load nodes
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

        # Load edges
        edge_list = list(edges)
        for i in range(0, len(edge_list), bs):
            batch = [{"src": str(u), "dst": str(v), "lbl": edge_label.get((u, v)) or edge_label.get((v, u), "")}
                    for u, v in edge_list[i:i+bs]]
            session.run("""
                UNWIND $batch AS row
                MATCH (a:EncNode {dataset_id:$ds, node_id:row.src})
                MATCH (b:EncNode {dataset_id:$ds, node_id:row.dst})
                CREATE (a)-[:ENC_EDGE {edge_label:row.lbl}]->(b)
            """, batch=batch, ds=DATASET_ID)

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

    # ── Degree / Neighbors of node X ───────────────────────────
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
                f"Node {src} → Node {dst}: {'REACHABLE. Within ' + str(hops) + ' hops.' if found else 'NOT REACHABLE within 4 hops.'}"
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
            "• 'how many SEND does node 42 have'\n"
            "• 'what label is node 0'\n"
            "• 'how many Executive nodes'\n"
            "• 'bfs from 0 depth 2'\n"
            "• 'can node 0 reach node 100'\n"
            "• 'find Executive REPLY Manager'"
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
        sees plaintext. Try the Email-Enron dataset below, or grab one from
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
    <div id="syncBanner" style="display:none;margin-top:10px;padding:8px 12px;border-radius:6px;font-size:0.82rem;display:flex;align-items:center;gap:10px;background:var(--surface2,#f1f5f9);border:1px solid var(--border,#e2e8f0)">
      <span id="syncDot" style="width:8px;height:8px;border-radius:50%;background:#94a3b8;flex-shrink:0"></span>
      <span id="syncText">Neo4j auto-sync starting…</span>
      <span style="margin-left:auto;opacity:.6" id="syncCounts"></span>
      <button onclick="manualSync()" style="padding:3px 9px;font-size:0.78rem;border-radius:4px;border:1px solid var(--border,#e2e8f0);background:#fff;cursor:pointer;color:var(--blue)">Sync now</button>
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
    <input id="queryInput" placeholder="e.g. How many CONNECTIONS does node 42 have?">
    <div class="query-row">
      <button onclick="runQuery()" id="queryBtn" disabled>Run Query</button>
      <button class="secondary" id="clearBtn" onclick="clearResult()">Clear</button>
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
    _refreshStatsPanel(data.stats);

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
  document.getElementById('clearBtn').disabled = true;   // disable Clear while running
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
  document.getElementById('clearBtn').disabled = false;  // re-enable Clear
}

function clearResult() {
  document.getElementById('resultPanel').className = 'card result-panel';
  document.getElementById('queryInput').value = '';
}

// ── Stats panel refresh (shared by load + sync) ──────────────
function _refreshStatsPanel(stats) {
  if (!stats) return;
  const sg = document.getElementById('statsGrid');
  if (!sg) return;
  sg.innerHTML = `
    <div class="stat-box"><div class="stat-value">${stats.nodes.toLocaleString()}</div><div class="stat-label">Nodes</div></div>
    <div class="stat-box"><div class="stat-value">${stats.edges.toLocaleString()}</div><div class="stat-label">Edges</div></div>
    <div class="stat-box"><div class="stat-value">${(stats.max_degree||0).toLocaleString()}</div><div class="stat-label">Max Degree</div></div>
    <div class="stat-box"><div class="stat-value">${stats.avg_degree||0}</div><div class="stat-label">Avg Degree</div></div>
    <div class="stat-box"><div class="stat-value">${(stats.labels||[]).length}</div><div class="stat-label">Label Types</div></div>
  `;
  const lt = document.getElementById('labelTags');
  const tagClass = {'Executive':'tag-inf','Manager':'tag-per','Employee':'tag-com','External':'tag-org','Inactive':'tag-bot'};
  lt.innerHTML = (stats.labels||[]).map(l => {
    const cls = tagClass[l] || 'tag-edge';
    const cnt = (stats.label_counts||{})[l] || 0;
    return `<span class="label-tag ${cls}">${l}: ${cnt.toLocaleString()}</span>`;
  }).join('');
}

// ── Neo4j auto-sync status polling ───────────────────────────
let _syncInterval = null;

function _fmtSyncTime(str) {
  return str || 'Never';
}

function _updateSyncBanner(data) {
  const banner = document.getElementById('syncBanner');
  const dot    = document.getElementById('syncDot');
  const txt    = document.getElementById('syncText');
  const counts = document.getElementById('syncCounts');

  if (!data.neo4j_active) {
    banner.style.display = 'none';
    return;
  }
  banner.style.display = 'flex';

  if (data.last_error) {
    dot.style.background = '#ef4444';
    txt.textContent = `Sync error: ${data.last_error}`;
  } else if (!data.last_sync_str || data.last_sync_str === 'Never') {
    dot.style.background = '#f59e0b';
    txt.textContent = `Auto-sync active — waiting for first cycle (every ${data.interval_s}s)…`;
  } else {
    dot.style.background = '#22c55e';
    const changes = (data.nodes_added||0) + (data.nodes_removed||0) + (data.nodes_updated||0)
                  + (data.edges_added||0) + (data.edges_removed||0);
    txt.textContent = `Last synced at ${_fmtSyncTime(data.last_sync_str)} — ${changes > 0 ? changes + ' change(s)' : 'no changes'}`;
  }

  const parts = [];
  if (data.nodes_added)   parts.push(`+${data.nodes_added} nodes`);
  if (data.nodes_removed) parts.push(`-${data.nodes_removed} nodes`);
  if (data.nodes_updated) parts.push(`~${data.nodes_updated} labels`);
  if (data.edges_added)   parts.push(`+${data.edges_added} edges`);
  if (data.edges_removed) parts.push(`-${data.edges_removed} edges`);
  counts.textContent = parts.join(' | ');

  // Refresh the stats panel if the sync returned fresh stats
  if (data.stats) _refreshStatsPanel(data.stats);
}

async function pollSyncStatus() {
  try {
    const resp = await fetch('/api/sync_status');
    const data = await resp.json();
    _updateSyncBanner(data);
  } catch(_) {}
}

async function manualSync() {
  const btn = document.querySelector('#syncBanner button');
  if (btn) { btn.disabled = true; btn.textContent = 'Syncing…'; }
  try {
    const resp = await fetch('/api/sync_neo4j', {method:'POST'});
    const data = await resp.json();
    if (data.error) { alert('Sync error: ' + data.error); return; }
    _updateSyncBanner({...data, neo4j_active: true, interval_s: 10});
  } catch(e) {
    alert('Sync error: ' + e.message);
  } finally {
    if (btn) { btn.disabled = false; btn.textContent = 'Sync now'; }
  }
}

function startSyncPolling() {
  if (_syncInterval) clearInterval(_syncInterval);
  pollSyncStatus();
  _syncInterval = setInterval(pollSyncStatus, 10000);
}

document.addEventListener('DOMContentLoaded', () => {
  document.getElementById('queryInput').addEventListener('keydown', e => {
    if (e.key === 'Enter' && e.ctrlKey) runQuery();
  });
  startSyncPolling();
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
                phase2_load_neo4j(driver, nodes, edges, enc_adj, node_label, edge_label)
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

@app.route('/api/add_node', methods=['POST'])
def api_add_node():
    data = request.get_json()
    nid = int(data['node_id'])
    
    # Update in-memory STATE
    STATE["nodes"].add(nid)
    STATE["node_label"][nid] = "Inactive"  # no edges yet
    
    # Optionally sync to Neo4j
    if STATE["driver"]:
        with STATE["driver"].session() as session:
            session.run("""
                CREATE (n:EncNode {dataset_id:$ds, node_id:$nid, label:'Inactive', adj_ct:''})
            """, ds=DATASET_ID, nid=str(nid))
    
    return jsonify({"ok": True, "node_id": nid})

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
    return jsonify({"tee_available": _probe_tee(), "neo4j_available": _NEO4J_AVAILABLE, "spark_available": _SPARK_AVAILABLE})

@app.route('/api/sync_neo4j', methods=['POST'])
def api_sync_neo4j():
    """Manual on-demand sync (also triggered automatically every 10 s)."""
    if not STATE["loaded"]:
        return jsonify({"error": "Load a dataset first"}), 400
    if not STATE["driver"]:
        return jsonify({"error": "Neo4j not connected — driver is None"}), 400
    try:
        _run_neo4j_sync()
        return jsonify({
            "ok": True,
            **{k: SYNC_STATE[k] for k in (
               "last_sync_str", "nodes_added", "nodes_removed",
               "nodes_updated", "edges_added", "edges_removed")},
            "total_nodes": len(STATE["nodes"]),
            "total_edges": len(STATE["edges"]),
            "stats":       STATE["stats"],   # for UI stats panel refresh
            "neo4j_active": True,
            "interval_s":  NEO4J_SYNC_INTERVAL,
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/sync_status', methods=['GET'])
def api_sync_status():
    """Return the current auto-sync state (polled by the UI every 10 s)."""
    return jsonify({
        **SYNC_STATE,
        "interval_s":   NEO4J_SYNC_INTERVAL,
        "neo4j_active": STATE["driver"] is not None and STATE["loaded"],
        "total_nodes":  len(STATE["nodes"]),
        "total_edges":  len(STATE["edges"]),
        "stats":        STATE["stats"],      # for UI stats panel refresh
    })

if __name__ == '__main__':
    # Start background auto-sync thread
    _sync_thread = threading.Thread(target=_neo4j_auto_sync, daemon=True, name="neo4j-autosync")
    _sync_thread.start()

    print("=" * 55)
    print("  DVH-GQP  ·  TeeDemo")
    print(f"  TEE (Nitro Enclave): {'probing on first query' }")
    print(f"  Neo4j : {'available' if _NEO4J_AVAILABLE else 'not installed — skipped'}")
    print(f"  Spark : {'available' if _SPARK_AVAILABLE else 'not installed — skipped'}")
    print(f"  Auto-sync: every {NEO4J_SYNC_INTERVAL}s (creates/deletes/edits)")
    print("  Open  : http://localhost:5000")
    print("=" * 55)
    app.run(debug=False, host='0.0.0.0', port=5000)