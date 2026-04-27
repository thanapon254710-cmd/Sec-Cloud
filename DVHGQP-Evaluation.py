from cProfile import label
import os, json, time, math, hashlib, random, gzip, urllib.request
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.gridspec as gridspec
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from neo4j import GraphDatabase
from collections import defaultdict
from dotenv import load_dotenv

# Fill in your Neo4j AuraDB credentials in the .env file with keys:
load_dotenv(dotenv_path=r"C:\Users\Thanapon\Desktop\SIIT\Sec+Cloud Project\.env")
CONFIG = {
    "NEO4J_URI": os.getenv("NEO4J_URI"),
    "NEO4J_USERNAME": os.getenv("NEO4J_USERNAME"),
    "NEO4J_PASSWORD": os.getenv("NEO4J_PASSWORD"),
    "BATCH_SIZE": int(os.getenv("BATCH_SIZE", 500)),
    "REPEAT": int(os.getenv("REPEAT", 10)),
}

# Simulation baseline values for TEE and Spark latencies based on AWS Nitro Enclaves and EMR benchmarks.
# TEE operation latencies
NITRO_ATTEST_MEAN_MS   = 68.0      # ms  — Nitro attestation mean latency
NITRO_ATTEST_STD_MS    =  6.0      # ms  — Nitro attestation std dev
NITRO_AES_PER_ENTRY_MS =  0.000500 # ms  — AES-NI decrypt per 64-byte entry

# Spark operation latencies
SPARK_SCHEDULE_MEAN_MS    = 80.0    # ms — task scheduling overhead per executor
SPARK_SCHEDULE_STD_MS     = 12.0    # ms — std dev (EMR variance)
SPARK_SHUFFLE_PER_NODE_MS =  0.005  # ms — shuffle cost per result node

SNAP_URL  = "https://snap.stanford.edu/data/facebook_combined.txt.gz"
DATA_PATH = "C:\\Users\\Thanapon\\Desktop\\SIIT\\Sec+Cloud Project\\facebook_combined.txt"

COLORS = {
    "dvhgqp":   "#2563EB",
    "baseline": "#DC2626",
    "oram":     "#16A34A",
    "dsse":     "#9333EA",
    "tee":      "#D97706",
    "spark":    "#0891B2",
}

random.seed(42)
np.random.seed(42)

# Cryptographic primitives
def keygen(): 
    return get_random_bytes(32)
 
def aes_gcm_encrypt(key, plaintext):
    c = AES.new(key, AES.MODE_GCM)
    ct, tag = c.encrypt_and_digest(plaintext)
    return c.nonce + tag + ct #in one blob for storage
 
def aes_gcm_decrypt(key, blob):
    n, tag, ct = blob[:16], blob[16:32], blob[32:]
    return AES.new(key, AES.MODE_GCM, nonce=n).decrypt_and_verify(ct,tag)
 
def prf(ks, w): 
    Tw = hashlib.sha256(ks+w.encode()).hexdigest()
    return Tw

PADDING_RATIO = 0.10
def pad_size(r): 
    return r + max(1, math.ceil(r * PADDING_RATIO))

# Simulate the latency of running inside an AWS Nitro Enclave (TEE)
def tee_cost(p_r):
    return random.gauss(NITRO_ATTEST_MEAN_MS,NITRO_ATTEST_STD_MS) + \
           NITRO_AES_PER_ENTRY_MS*p_r

# Simulate Apache Spark distributed execution 
def spark_cost(k, shard_size):
    t_schedule = sum(random.gauss(SPARK_SCHEDULE_MEAN_MS, SPARK_SCHEDULE_STD_MS)
                     for _ in range(k))
    t_shuffle  = SPARK_SHUFFLE_PER_NODE_MS * shard_size
    return t_schedule + t_shuffle
 
# ── Phase 0 ─────────────────────────────────────────────
def download_snap():
    gz = DATA_PATH + ".gz"
    if not os.path.exists(DATA_PATH):
        print("[Phase 0] Downloading ego-Facebook...")
        urllib.request.urlretrieve(SNAP_URL, gz)
        with gzip.open(gz,"rb") as fi, open(DATA_PATH,"wb") as fo: fo.write(fi.read())
        os.remove(gz)
    else:
        print(f"[Phase 0] Dataset present.")
 
def load_snap_graph():
    edges, nodes = [], set()
    with open(DATA_PATH) as f:
        for line in f:
            line = line.strip()
            if line.startswith("#") or not line: continue # skip comments/empty
            u, v = map(int,line.split())
            edges.append((u,v))
            nodes.add(u) 
            nodes.add(v)
    print(f"[Phase 0] Loaded: {len(nodes)} nodes, {len(edges)} edges")
    return nodes, edges
 
NODE_LABELS = ["Person", "Influencer", "Community", "Organization", "Bot"]
EDGE_LABELS = ["FRIEND", "FOLLOWS", "MEMBER_OF" ,"INTERACTS"]
 
def assign_labels(nodes, edges):
    degree = {}
    for u, v in edges: 
        degree[u] = degree.get(u,0) + 1
        degree[v] = degree.get(v,0) + 1
    node_label = {}
    for n in nodes:
        d=degree.get(n,0)
        if   d > 200: node_label[n]="Influencer"
        elif d > 50:  node_label[n]="Community"
        elif d > 10:  node_label[n]="Person"
        elif d > 2:   node_label[n]="Organization"
        else:       node_label[n]="Bot"
    edge_label = {(u,v):EDGE_LABELS[(u+v)%4] for u,v in edges}
    return node_label, edge_label
 
# ── Phase 1: Encrypt + DSSE + Adjacency Index ────────────
def phase1_encrypt(nodes, edges, node_label, edge_label, K, Ks, Ke):
    print("[Phase 1] Encrypting graph blocks...")
    t0 = time.perf_counter() # start timer for phase 1
 
    enc_nodes = {}
    for v in nodes:
        node_data = {
                    "id":    v,
                    "label": node_label[v],
                    "attrs": {}
                    }
        # Serialize to JSON string, then encode to bytes
        node_bytes = json.dumps(node_data).encode()

        # Encrypt with AES-GCM using key K
        encrypted = aes_gcm_encrypt(K, node_bytes)

        # Convert bytes → hex string for Neo4j storage
        enc_nodes[v] = encrypted.hex()

    enc_edges = {}
    for (u, v) in edges:
        edge_data = {
                    "src":   u,
                    "dst":   v,
                    "label": edge_label[(u, v)],
                    "attrs": {}
                    }
        # Serialize to JSON string, then encode to bytes
        edge_bytes = json.dumps(edge_data).encode()

        # Encrypt with AES-GCM using key K
        encrypted = aes_gcm_encrypt(K, edge_bytes)

        # Store with (u,v) tuple as key
        enc_edges[(u, v)] = encrypted.hex()
    
    enc_time = (time.perf_counter() - t0) * 1000
    print(f"          Encrypted {len(enc_nodes)} nodes + {len(enc_edges)} edges in {enc_time:.0f}ms")
 
    # DSSE label index
    print("[Phase 1] Building DSSE label index...")
    hist={}
    for v, lbl in node_label.items():
        if lbl not in hist:
            hist[lbl] = []          # first time seeing this label → create list
        hist[lbl].append(("v", v)) # "v" marks this as a vertex/node entry

    for (u, v), lbl in edge_label.items():
        if lbl not in hist:
            hist[lbl] = []          # first time seeing this label → create list
        hist[lbl].append(("e", u, v))  # "e" marks this as an edge entry

    dsse_index = {}
    total_real = total_dummy = 0
    for w, real_ids in hist.items():
        r = len(real_ids) # true result count
        p = pad_size(r)   # padded count

        # Serialize real entries to JSON strings
        real_e = []
        for x in real_ids:
            as_list   = list(x)          
            as_string = json.dumps(as_list) 
            real_e.append(as_string)

        # Generate dummy entries to fill up to p ──
        dummy_e = []
        for i in range(p - r): # how many dummies needed
            dummy_string = json.dumps(f"__dummy_{i}__{w}")
            dummy_e.append(dummy_string)

        # Encrypt all entries (real + dummy) with Ke and store in DSSE index
        all_entries = real_e + dummy_e   # real first, then dummies
        enc_list = []
        for e in all_entries:
            as_bytes  = e.encode()                      # string >> bytes
            encrypted = aes_gcm_encrypt(Ke, as_bytes)   # encrypt with Ke
            as_hex    = encrypted.hex()                 # bytes >> hex string
            enc_list.append(as_hex)

        # prf hashes the label name so Neo4j never sees "Person" as a key
        hashed_key = prf(Ks, w)
        dsse_index[hashed_key] = {
                                "entries": enc_list,   # p encrypted blobs
                                "p_r":     p,          # padded size
                                "label":   w           # original label (kept client-side)
                                }
        total_real += r       # count real entries
        total_dummy += p - r  # count dummy entries
    print("[Phase 1] Building encrypted adjacency index...")

    # Encrypted adjacency index 
    # Each node stores an encrypted list of (neighbor_id, edge_label) pairs
    adj_plain = defaultdict(list)
    for u, v in edges:
        lbl = edge_label[(u,v)]
        adj_plain[u].append((v,lbl))
        adj_plain[v].append((u,lbl))  # undirected
 
    enc_adj = {}
    for node, neighbors in adj_plain.items():
        # Serialize entire neighbor list to JSON string
        as_json = json.dumps(neighbors)

        # Encode string to bytes
        as_bytes = as_json.encode()

        # Encrypt the whole list as ONE blob with key K
        encrypted = aes_gcm_encrypt(K, as_bytes)

        # Convert to hex string for Neo4j storage
        enc_adj[node] = encrypted.hex()
 
    index_time = (time.perf_counter()-t0) * 1000 - enc_time
    print(f"          Adjacency index: {len(enc_adj)} nodes in {index_time:.0f}ms")
 
    stats = {"enc_time_ms":enc_time,       "index_time_ms":index_time,
             "total_nodes":len(enc_nodes), "total_edges":len(enc_edges),
             "total_real":total_real,      "total_dummy":total_dummy,
             "storage_ratio":round((total_real + total_dummy) / max(total_real,1) ,3),
             "num_labels":len(hist)}
    return enc_nodes, enc_edges, enc_adj, dsse_index, hist, dict(adj_plain), stats
 
# ── Phase 2: Load Neo4j ──────────────────────────────────
def phase2_load_neo4j(driver, enc_nodes, enc_edges, enc_adj):
    print("[Phase 2] Loading into Neo4j AuraDB...")
    bs = CONFIG["BATCH_SIZE"] # batch size for Neo4j transactions

    with driver.session() as session:
        session.run("MATCH (n) DETACH DELETE n")
        print("          Cleared existing graph.")
    
        node_list = list(enc_nodes.items())
        for i in range(0, len(node_list), bs):
            chunk = node_list[i : i+bs] # 500 items at a time
            batch = []
            for nid, ct in chunk:
                batch.append({
                    "nid":    str(nid),              # node ID
                    "ct":     ct,                    # encrypted node blob
                    "adj_ct": enc_adj.get(nid, "")   # encrypted neighbor list
                })
            session.run("""
                        UNWIND $batch AS row  
                        CREATE (n:EncNode {
                            node_id:row.nid, 
                            ciphertext:row.ct,
                            adj_ct:row.adj_ct, 
                            block_type:'vertex'})
                        """, batch=batch)
            print(f"          Nodes: {min(i+bs,len(node_list))}/{len(node_list)}", end="\r")
        print(f"\n          Loaded {len(enc_nodes)} nodes.")
        # Create index on node_id for fast lookup later
        session.run("CREATE INDEX enc_node_id IF NOT EXISTS FOR (n:EncNode) ON (n.node_id)")
        edge_list = list(enc_edges.items())
        for i in range(0, len(edge_list), bs):
            chunk = edge_list[i : i+bs]
            batch = []
            for (u, v), ct in chunk:
                batch.append({
                    "src": str(u),   # source node ID
                    "dst": str(v),   # destination node ID
                    "ct":  ct        # encrypted edge blob
                })
            session.run("""
                            UNWIND $batch AS row
                            MATCH (a:EncNode {node_id:row.src})
                            MATCH (b:EncNode {node_id:row.dst})
                            CREATE (a)-[:ENC_EDGE {ciphertext:row.ct}]->(b)
                        """, batch=batch)
            print(f"          Edges: {min(i+bs,len(edge_list))}/{len(edge_list)}", end="\r")
        print(f"\n          Loaded {len(enc_edges)} edges.")
    print("[Phase 2] Load complete.")
 
# ── Neo4j fetch helper ───────────────────────────────────
def fetch_nodes(driver, node_ids, p_r): # DVHGQP - Fetch exactly P(r) node blocks from Neo4j — Selective ORAM simulation
    t0 = time.perf_counter()
    total_nodes = 4039 #total nodes in Facebook dataset
    with driver.session() as session:
        real_fetch = min(len(node_ids), p_r)
        ids_to_fetch = [str(x) for x in node_ids[:real_fetch]] # convert to strings for Neo4j query
        res = session.run("""
                            UNWIND $ids AS nid 
                            MATCH (n:EncNode {node_id:nid})
                            RETURN n.node_id AS nid, 
                                   n.ciphertext AS ct, 
                                   n.adj_ct AS adj_ct
                          """, ids = ids_to_fetch)
        records = list(res)
        dummy_needed = p_r - real_fetch         
        # e.g. p_r=55, real_fetch=50 → need 5 dummy nodes
        if dummy_needed > 0:
            skip = (p_r * 7) % max(1, total_nodes - dummy_needed) # deterministic skip for dummy selection
            # e.g. p_r=55 → skip = (55*7) % 4034 = 385 % 4034 = 385
            dummy = session.run("""
                                    MATCH (n:EncNode)
                                    RETURN n.node_id AS nid, 
                                           n.ciphertext AS ct, 
                                           n.adj_ct AS adj_ct
                                    SKIP $skip LIMIT $lim
                                """, skip = skip, lim = dummy_needed)
                                # SKIP = jump past first 385 nodes
                                # LIMIT = take only dummy_needed nodes after that
            records += list(dummy) # Append dummies to real records
    return records, (time.perf_counter() - t0) * 1000
 
def fetch_nodes_plain(driver, node_ids): # Baseline
    """Fetch exactly r blocks — baseline (no ORAM padding)."""
    t0 = time.perf_counter()
    with driver.session() as session:
        res = session.run("""
            UNWIND $ids AS nid MATCH (n:EncNode {node_id:nid})
            RETURN n.node_id AS nid, n.ciphertext AS ct, n.adj_ct AS adj_ct
        """, ids=[str(x) for x in node_ids])
        records = list(res)
    return records, (time.perf_counter()-t0)*1000

# ── Phase 3b: BFS REACHABILITY QUERY ────────────────────
def bfs_query(driver, K, adj_plain, start_node, max_depth=3, k=4): # DVHGQP - BFS traversal up to max_depth
    t0_total = time.perf_counter()
    visited = {start_node}  # track visited nodes
    frontier = [start_node] # nodes to explore at current depth
    level_stats = []
    t_neo4j_tot = t_tee_tot = t_spark_tot = 0.0 # running totals
 
    for depth in range(1, max_depth + 1):
        if not frontier: 
            break # no more nodes to explore
        r_frontier = len(frontier) # number of nodes in current frontier
        p_r = pad_size(r_frontier) # padded size for ORAM fetch
        f_r = math.ceil(p_r/k)     # shard size for Spark parallelism
 
        # ORAM: fetch P(r) adjacency blocks from Neo4j
        records, t_neo4j = fetch_nodes(driver, frontier, p_r)
        t_neo4j_tot += t_neo4j
 
        # TEE: decrypt adj_ct, extract neighbors, discard dummies
        t_tee = tee_cost(p_r)
        t_tee_tot += t_tee
 
        new_frontier = []
        frontier_set = set(frontier)
        for rec in records:
            try:
                nid = int(rec["nid"])
                if nid not in frontier_set: 
                    continue  # dummy - skip

                adj_hex = rec["adj_ct"]
                if not adj_hex: 
                    continue  # no neighbors - skip

                adj_bytes    = bytes.fromhex(adj_hex)
                decrypted    = aes_gcm_decrypt(K, adj_bytes)
                as_string    = decrypted.decode()
                neighbors    = json.loads(as_string) # list of (neighbor_id, edge_label)     
                for nbr, elbl in neighbors:
                    if nbr not in visited:
                        visited.add(nbr)             # mark as visited
                        new_frontier.append(nbr)     # add to next frontier
            except Exception:
                continue  # dummy block — silently discard
 
        # Spark: parallel frontier verification across k executors
        shard = max(1, len(new_frontier) // k)
        t_spark = spark_cost(k, shard)
        t_spark_tot += t_spark
 
        level_stats.append({"depth":depth, "frontier_r":r_frontier, "p_r":p_r,
                            "f_r":f_r, "new_nodes":len(new_frontier), "visited":len(visited),
                            "t_neo4j_ms":round(t_neo4j,2), "t_tee_ms":round(t_tee,2),
                            "t_spark_ms":round(t_spark,2),
                            "t_level_ms":round(t_neo4j+t_tee+t_spark,2)})
        frontier = new_frontier    # move to next level
 
    t_total = (time.perf_counter() - t0_total) * 1000 + t_spark_tot
    return {"start_node":start_node, "max_depth":max_depth, "k":k,
            "total_visited":len(visited),  "t_neo4j_ms":round(t_neo4j_tot,2),
            "t_tee_ms":round(t_tee_tot,2), "t_spark_ms":round(t_spark_tot,2),
            "t_total_ms":round(t_total,2), "level_stats":level_stats}
 
def baseline_bfs(driver, K, adj_plain, start_node, max_depth=3): # Baseline - BFS without ORAM padding, TEE and Spark costs
    t0_total = time.perf_counter()
    visited = {start_node}; frontier = [start_node]
    t_neo4j_tot = 0.0

    for depth in range(1, max_depth+1):
        if not frontier: break

        # Fetch only real r blocks — no padding
        records, t_neo4j = fetch_nodes_plain(driver, frontier)
        t_neo4j_tot += t_neo4j

        new_frontier = []; frontier_set = set(frontier)
        for rec in records:
            try:
                nid = int(rec["nid"])
                if nid not in frontier_set: continue
                adj_hex = rec["adj_ct"]
                if not adj_hex: continue
                neighbors = json.loads(aes_gcm_decrypt(K, bytes.fromhex(adj_hex)).decode())
                for nbr,_ in neighbors:
                    if nbr not in visited:
                        visited.add(nbr); new_frontier.append(nbr)
            except: continue
        frontier = new_frontier

    t_total = (time.perf_counter()-t0_total)*1000
    return {"visited": len(visited),
            "t_neo4j_ms": round(t_neo4j_tot,2),
            "t_tee_ms":   0.0,
            "t_spark_ms": 0.0,
            "t_total_ms": round(t_total,2)}

# ── Phase 3c: SUBGRAPH MATCHING QUERY ────────────────────
def subgraph_match_query(driver, K, adj_plain, node_label, pattern, k=4): # DVHGQP - find pattern matches
    t0 = time.perf_counter()
    # Full pattern = "Influencer -[FOLLOWS]-> Person"
    src_lbl  = pattern["src_label"] # Influencer
    edge_lbl = pattern["edge_label"] # FOLLOWS
    dst_lbl  = pattern["dst_label"]   # Person
    candidates = []
    for n, lbl in node_label.items():
        if lbl == src_lbl:
            candidates.append(n)
    r = len(candidates)
    p_r = pad_size(r)
    t_dsse = 0.001   # assumes DSSE token lookup is near-instant

    records, t_neo4j = fetch_nodes(driver,candidates,p_r)
    t_tee = tee_cost(p_r)
 
    matches = []
    for rec in records:
        try:
            nid = int(rec["nid"])
            if node_label.get(nid) != src_lbl: 
                continue    # dummy or wrong label - skip

            adj_hex = rec["adj_ct"]
            if not adj_hex: 
                continue    # no neighbors - skip

            adj_bytes = bytes.fromhex(adj_hex)
            decrypted = aes_gcm_decrypt(K, adj_bytes)
            neighbors = json.loads(decrypted.decode())
            for nbr, elbl in neighbors:
                if elbl == edge_lbl and node_label.get(nbr) == dst_lbl: # found a match for the pattern
                    matches.append((nid, nbr))
        except Exception: 
            continue
 
    shard = max(1, len(candidates) // k)
    t_spark = spark_cost(k, shard)
    t_total = (time.perf_counter() - t0) * 1000 + t_spark
 
    return {"pattern":f"{src_lbl}-[{edge_lbl}]->{dst_lbl}",
            "candidates":r, "p_r":p_r, "matches":len(matches), "k":k,
            "t_dsse_ms":round(t_dsse,4),   "t_tee_ms":round(t_tee,2),
            "t_neo4j_ms":round(t_neo4j,2), "t_spark_ms":round(t_spark,2),
            "t_total_ms":round(t_total,2)}
 
def baseline_subgraph(driver, K, node_label, pattern): # Baseline - without ORAM padding, TEE and Spark costs
    t0 = time.perf_counter()
    src_lbl = pattern["src_label"]; edge_lbl = pattern["edge_label"]; dst_lbl = pattern["dst_label"]
    candidates = [n for n,lbl in node_label.items() if lbl==src_lbl]
    r = len(candidates)

    records, t_neo4j = fetch_nodes_plain(driver, candidates)

    matches = []
    for rec in records:
        try:
            nid = int(rec["nid"])
            if node_label.get(nid) != src_lbl: continue
            adj_hex = rec["adj_ct"]
            if not adj_hex: continue
            neighbors = json.loads(aes_gcm_decrypt(K, bytes.fromhex(adj_hex)).decode())
            for nbr,elbl in neighbors:
                if elbl==edge_lbl and node_label.get(nbr)==dst_lbl:
                    matches.append((nid,nbr))
        except: continue

    t_total = (time.perf_counter()-t0)*1000
    return {"candidates": r, "matches": len(matches),
            "t_neo4j_ms": round(t_neo4j,2), "t_tee_ms": 0.0,
            "t_spark_ms": 0.0, "t_total_ms": round(t_total,2)}

# ── Phase 3a: Label lookup ───────────────────────────────
def dsse_lookup(dsse_index, Ks, Ke, K, query_label): # Look up a label in the DSSE index, decrypt results in TEE, and return real IDs + p(r)
    t0 = time.perf_counter()    # start timer for DSSE lookup
    token = prf(Ks,query_label)     # hash the label to get DSSE token
    entry = dsse_index.get(token)   # look up in DSSE index using token
    if entry is None: 
        return [], [], 0, (time.perf_counter() - t0) * 1000, 0.0, 0
    all_entries = entry["entries"]; 
    p_r = entry["p_r"]
    t_dsse = (time.perf_counter() - t0) * 1000

    t1 = time.perf_counter()    # start timer for TEE decryption
    real_ids = []
    for h in all_entries:
        as_bytes = bytes.fromhex(h)
        decrypted = aes_gcm_decrypt(Ke, as_bytes)
        parsed = json.loads(decrypted.decode())
        real_ids.append(parsed)
    real_ids = [x for x in real_ids if isinstance(x, list)]
    t_tee_dec = (time.perf_counter() - t1) * 1000
    return real_ids ,p_r, t_dsse, t_tee_dec, len(real_ids)
 
def fetch_blocks_label(driver, node_ids, p_r): # fetch exactly p_r blocks from Neo4j, simulating selective ORAM with dummy fetches
    t0 = time.perf_counter()
    total_nodes = 4039
    with driver.session() as session:
        real_fetch = min(len(node_ids),p_r)
        ids_to_fetch = [str(x) for x in node_ids[:real_fetch]]
        res = session.run("""
                            UNWIND $ids AS nid 
                            MATCH (n:EncNode {node_id:nid})
                            RETURN n.node_id AS nid, 
                                   n.ciphertext AS ct
                          """, ids = ids_to_fetch)
        records = list(res)
        dummy_needed = p_r - real_fetch
        if dummy_needed > 0:
            skip = (p_r * 7) % max(1, total_nodes - dummy_needed)
            dummy = session.run("""
                                    MATCH (n:EncNode)
                                    RETURN n.node_id AS nid, 
                                           n.ciphertext AS ct
                                    SKIP $skip LIMIT $lim
                                """,skip = skip, lim = dummy_needed)
            records += list(dummy)
    return records, (time.perf_counter() - t0) * 1000
 
def run_label_query(driver, dsse_index, Ks, Ke, K, label, k=4): #  Find all nodes with a given label
    real_ids, p_r, t_dsse, _, r_true = dsse_lookup(dsse_index, Ks, Ke, K, label)
    if r_true == 0: 
        return None # Label doesn't exist in index, skip this query
    node_ids = []
    for e in real_ids:
        if e[0] == "v":              # "v" = vertex/node entry
            node_ids.append(e[1])    # extract node ID from entry
    t_tee = tee_cost(p_r)
    records, t_neo4j = fetch_blocks_label(driver, node_ids, p_r)
    t2 = time.perf_counter()    # start timer for decryption
    for rec in records: 
        as_bytes  = bytes.fromhex(rec["ct"])
        decrypted = aes_gcm_decrypt(K, as_bytes)
    t_decrypt = (time.perf_counter() - t2) * 1000
    shard = max(1, r_true // k)
    t_spark = spark_cost(k, shard)
    total = t_dsse + t_tee + t_neo4j + t_decrypt + t_spark
    return {"label":label, "r_true":r_true, "p_r":p_r, "k":k,
            "t_dsse_ms":round(t_dsse,3),   "t_tee_ms":round(t_tee,3),
            "t_neo4j_ms":round(t_neo4j,3), "t_decrypt_ms":round(t_decrypt,3),
            "t_spark_ms":round(t_spark,3), "t_total_ms":round(total,3),
            "blocks_fetched":len(records)}
 
def run_label_benchmark(driver, dsse_index, Ks, Ke, K, hist):
    print("[Phase 3a] Label lookup benchmark...")
    results = []
    for label in hist:
        for k in [2, 4, 8]:    # test different levels of Spark parallelism
            runs = []
            for _ in range(CONFIG["REPEAT"]):   # REPEAT = 10
                result = run_label_query(driver, dsse_index, Ks, Ke, K, label, k=k)
                runs.append(result)
            runs = [r for r in runs if r] # filter out None results (labels that didn't exist)
            
            if runs:
                avg = {}
                for key in runs[0]:
                    if isinstance(runs[0][key], (int, float)):    # only average numeric fields
                        values = []
                        for r in runs:
                            if isinstance(r[key], (int, float)):  # ensure this field is numeric in all runs
                                values.append(r[key])
                        avg[key] = round(np.mean(values), 3)
                # Add back string fields manually
                avg["label"] = label   
                avg["k"]     = k     
                results.append(avg)
                print(f"           [{label},k={k}] total={avg['t_total_ms']}ms")
    return results
 
def run_bfs_benchmark(driver, K, adj_plain, node_label, degree):
    print("[Phase 3b] BFS Reachability benchmark...")
    high_deg = sorted(node_label,                    # all node IDs
                      key=lambda n:degree.get(n,0),  # sort nodes by degree
                      reverse=True)                  # high degree first
    start_nodes = {"high_degree":high_deg[0],
                   "mid_degree" :high_deg[len(high_deg)//4],
                   "low_degree" :high_deg[-1]}
    
    dvhgqp_rows = []
    baseline_rows = []
    for cls, start in start_nodes.items():
        for depth in [1, 2, 3]:
             for k in [2, 4, 8]:
                # DVH-GQP \
                runs_d = []
                for _ in range(CONFIG["REPEAT"]):  
                    result_d = bfs_query(driver, K, adj_plain, start, max_depth=depth, k=k)
                    runs_d.append(result_d)
                dvhgqp_rows.append({
                    "class": cls, "start_degree": degree.get(start,0),
                    "depth": depth, "scheme": "DVH-GQP", "k": k,
                    "visited":     round(np.mean([r["total_visited"]    for r in runs_d])),
                    "t_neo4j_ms":  round(np.mean([r["t_neo4j_ms"] for r in runs_d]),2),
                    "t_tee_ms":    round(np.mean([r["t_tee_ms"]   for r in runs_d]),2),
                    "t_spark_ms":  round(np.mean([r["t_spark_ms"] for r in runs_d]),2),
                    "t_total_ms":  round(np.mean([r["t_total_ms"] for r in runs_d]),2),
                })

                # Baseline
                runs_b = []
                for _ in range(CONFIG["REPEAT"]): 
                    result_b     = baseline_bfs(driver, K, adj_plain, start, max_depth=depth)
                    runs_b.append(result_b)
                baseline_rows.append({
                    "class": cls, "start_degree": degree.get(start,0),
                    "depth": depth, "k": k, "scheme": "Baseline",
                    "visited":     round(np.mean([r["visited"]    for r in runs_b])),
                    "t_neo4j_ms":  round(np.mean([r["t_neo4j_ms"] for r in runs_b]),2),
                    "t_tee_ms":    0.0, "t_spark_ms": 0.0,
                    "t_total_ms":  round(np.mean([r["t_total_ms"] for r in runs_b]),2),
                })

                print(f"           BFS [{cls} D={depth}] DVH-GQP={dvhgqp_rows[-1]['t_total_ms']}ms  "
                    f"Baseline={baseline_rows[-1]['t_total_ms']}ms")
                
    return dvhgqp_rows, baseline_rows
 
def run_subgraph_benchmark(driver, K, adj_plain, node_label):
    print("[Phase 3c] Subgraph Matching benchmark...")
    patterns = [
        {"src_label":"Influencer","edge_label":"FOLLOWS",  "dst_label":"Person"},
        {"src_label":"Person",    "edge_label":"FRIEND",   "dst_label":"Person"},
        {"src_label":"Community", "edge_label":"MEMBER_OF","dst_label":"Person"},
        {"src_label":"Bot",       "edge_label":"INTERACTS","dst_label":"Person"},
    ]

    dvhgqp_rows = []
    baseline_rows = []
    for pattern in patterns:
        label = f"{pattern['src_label']}-[{pattern['edge_label']}]->{pattern['dst_label']}"
        # DVH-GQP (k=4) Spark parallel
        runs_d = []
        for _ in range(CONFIG["REPEAT"]):
            result_d = subgraph_match_query(driver, K, adj_plain, node_label, pattern, k=4)
            runs_d.append(result_d)
        dvhgqp_rows.append({"pattern":runs_d[0]["pattern"], "candidates":runs_d[0]["candidates"],
               "p_r":runs_d[0]["p_r"], "matches":runs_d[0]["matches"], "k":4,
               "t_tee_ms"  :round(np.mean([r["t_tee_ms"] for r in runs_d]),2),
               "t_neo4j_ms":round(np.mean([r["t_neo4j_ms"] for r in runs_d]),2),
               "t_spark_ms":round(np.mean([r["t_spark_ms"] for r in runs_d]),2),
               "t_total_ms":round(np.mean([r["t_total_ms"] for r in runs_d]),2)})

        # Baseline
        runs_b = []
        for _ in range(CONFIG["REPEAT"]):
            result_b = baseline_subgraph(driver, K, node_label, pattern)
            runs_b.append(result_b)
        baseline_rows.append({
            "pattern": label, "scheme": "Baseline",
            "candidates": runs_b[0]["candidates"], "p_r": runs_b[0]["candidates"],
            "matches":    runs_b[0]["matches"],
            "t_neo4j_ms": round(np.mean([r["t_neo4j_ms"] for r in runs_b]),2),
            "t_tee_ms":   0.0, "t_spark_ms": 0.0,
            "t_total_ms": round(np.mean([r["t_total_ms"] for r in runs_b]),2),
        })

        print(f"  Subgraph [{label}] DVH-GQP={dvhgqp_rows[-1]['t_total_ms']}ms  "
              f"Baseline={baseline_rows[-1]['t_total_ms']}ms")
    
    return dvhgqp_rows, baseline_rows
 
# ── Phase 4: Plots ───────────────────────────────────────
def make_evaluation_plots(label_results, bfs_results, sg_results, phase1_stats, out_dir="outputs"):
    os.makedirs(out_dir, exist_ok=True)
    df_lbl = pd.DataFrame(label_results)
    df_bfs = pd.DataFrame(bfs_results)
    df_sg  = pd.DataFrame(sg_results)
    df_k4  = df_lbl[df_lbl["k"]==4].copy()  # ← restore this for label plots (Fig 3 & 4)
    df_bk4 = df_bfs     

    fig = plt.figure(figsize=(20,28))
    gs  = gridspec.GridSpec(4, 2, hspace=0.50, wspace=0.35)
 
    # Fig 3: Label latency breakdown
    ax1 = fig.add_subplot(gs[0,0])
    x   = np.arange(len(df_k4)); 
    w   = 0.18
    ax1.bar(x-2*w,df_k4["t_dsse_ms"],   w,label="DSSE",   color=COLORS["dsse"],  alpha=0.88)
    ax1.bar(x-1*w,df_k4["t_tee_ms"],    w,label="TEE",    color=COLORS["tee"],   alpha=0.88)
    ax1.bar(x,    df_k4["t_neo4j_ms"],  w,label="Neo4j",  color=COLORS["oram"],  alpha=0.88)
    ax1.bar(x+1*w,df_k4["t_decrypt_ms"],w,label="Decrypt", color="#0891B2",    alpha=0.88)
    ax1.bar(x+2*w,df_k4["t_spark_ms"],  w,label="Spark",  color=COLORS["spark"], alpha=0.88)
    ax1.set_xticks(x); ax1.set_xticklabels(df_k4["label"], rotation=30, ha="right")
    ax1.set_ylabel("Latency (ms)")
    ax1.set_title("Fig. 3: Label Query Latency Breakdown (k=4)", fontweight="bold")
    ax1.legend(fontsize=9); ax1.grid(True, alpha=0.3, axis="y")
 
    # Fig 4: Total latency vs r
    ax2 = fig.add_subplot(gs[0,1])
    for ki, kv in enumerate([2,4,8]):
        sub = df_lbl[df_lbl["k"]==kv].sort_values("r_true")
        ax2.plot(sub["r_true"], sub["t_total_ms"], "o-", lw=2, label=f"k={kv}",
                 color=[COLORS["dvhgqp"], COLORS["oram"], COLORS["tee"]][ki])
    ax2.set_xlabel("True Result Size r")
    ax2.set_ylabel("Total Latency (ms)")
    ax2.set_title("Fig. 4: Label Query Latency vs. r",fontweight="bold")
    ax2.legend(); ax2.grid(True, alpha=0.3)
 
    # Fig 5: BFS latency vs depth
    ax3 = fig.add_subplot(gs[1,0])
    for cls, color in [("high_degree", COLORS["dvhgqp"]), ("mid_degree",COLORS["oram"]), ("low_degree",COLORS["tee"])]:
        sub = df_bk4[df_bk4["class"]==cls].sort_values("depth")
        if not sub.empty:
            ax3.plot(sub["depth"], sub["t_total_ms"], "o-" ,lw=2,
                     label = f"{cls} (deg={sub.iloc[0]['start_degree']})", color=color)
    ax3.set_xlabel("BFS Depth D") 
    ax3.set_ylabel("Total Latency (ms)")
    ax3.set_title("Fig. 5: BFS Reachability Latency vs. Depth\n(k=4, real graph traversal)", fontweight="bold")
    ax3.legend(fontsize=9)
    ax3.grid(True, alpha=0.3)
    ax3.set_xticks([1,2,3])
 
    # Fig 6: BFS visited nodes vs depth
    ax4 = fig.add_subplot(gs[1,1])
    for cls, color in [("high_degree",COLORS["dvhgqp"]), ("mid_degree",COLORS["oram"]), ("low_degree",COLORS["tee"])]:
        sub = df_bk4[df_bk4["class"]==cls].sort_values("depth")
        if not sub.empty:
            ax4.plot(sub["depth"], sub["visited"], "s-", lw=2, label=cls, color=color)
    ax4.set_xlabel("BFS Depth D")
    ax4.set_ylabel("Nodes Visited")
    ax4.set_title("Fig. 6: BFS — Nodes Visited vs. Depth", fontweight="bold")
    ax4.legend(fontsize=9)
    ax4.grid(True,alpha=0.3)
    ax4.set_xticks([1,2,3])
 
    # Fig 7: BFS k comparison at depth=2
    ax5=fig.add_subplot(gs[2,0])
    df_d2 = df_bfs[df_bfs["depth"]==2]
    for cls, color in [("high_degree", COLORS["dvhgqp"]), ("mid_degree",COLORS["oram"]), ("low_degree",COLORS["tee"])]:
        sub = df_d2[df_d2["class"]==cls].sort_values("k")
        if not sub.empty:
            ax5.plot(sub["k"], sub["t_total_ms"], "o-", lw=2, label=cls, color=color)
    ax5.set_xlabel("Spark Parallelism k")
    ax5.set_ylabel("Total Latency (ms)")
    ax5.set_title("Fig. 7: BFS Latency vs. k (Depth=2)", fontweight="bold")
    ax5.set_xticks([2,4,8])
    ax5.legend(fontsize=9)
    ax5.grid(True, alpha=0.3)
 
    # Fig 8: BFS component breakdown
    ax6 = fig.add_subplot(gs[2,1])
    df_high_k4 = df_bfs[(df_bfs["class"]=="high_degree")&(df_bfs["k"]==4)].sort_values("depth")
    if not df_high_k4.empty:
        depths = df_high_k4["depth"].tolist()
        ax6.bar([d-0.2 for d in depths],df_high_k4["t_tee_ms"],   0.2,label="TEE",  color=COLORS["tee"],  alpha=0.88)
        ax6.bar(depths,                 df_high_k4["t_neo4j_ms"], 0.2,label="Neo4j",color=COLORS["oram"], alpha=0.88)
        ax6.bar([d+0.2 for d in depths],df_high_k4["t_spark_ms"], 0.2,label="Spark",color=COLORS["spark"],alpha=0.88)
    ax6.set_xlabel("BFS Depth D")
    ax6.set_ylabel("Latency (ms)")
    ax6.set_title("Fig. 8: BFS Latency Component Breakdown\n(high-degree node, k=4)",fontweight="bold")
    ax6.set_xticks([1,2,3])
    ax6.legend(fontsize=9)
    ax6.grid(True, alpha=0.3, axis="y")
 
    # Fig 9: Subgraph matching latency
    ax7 = fig.add_subplot(gs[3,0])
    df_sg_k4 = df_sg[df_sg["k"]==4]
    x = np.arange(len(df_sg_k4))
    w = 0.25
    ax7.bar(x-w,df_sg_k4["t_tee_ms"],  w,label="TEE",  color=COLORS["tee"],  alpha=0.88)
    ax7.bar(x,  df_sg_k4["t_neo4j_ms"],w,label="Neo4j",color=COLORS["oram"], alpha=0.88)
    ax7.bar(x+w,df_sg_k4["t_spark_ms"],w,label="Spark",color=COLORS["spark"],alpha=0.88)
    ax7.set_xticks(x)
    ax7.set_xticklabels([p[:22] for p in df_sg_k4["pattern"]], rotation=20, ha="right", fontsize=8)
    ax7.set_ylabel("Latency (ms)")
    ax7.set_title("Fig. 9: Subgraph Matching Latency by Pattern (k=4)",fontweight="bold")
    ax7.legend(fontsize=9)
    ax7.grid(True, alpha=0.3, axis="y")
 
    # Fig 10: Matches found vs candidates
    ax8 = fig.add_subplot(gs[3,1])
    ax8.bar(range(len(df_sg_k4)),df_sg_k4["candidates"],color=COLORS["dvhgqp"],label="Candidates P(r)",alpha=0.88)
    ax8.bar(range(len(df_sg_k4)),df_sg_k4["matches"],   color=COLORS["oram"],  label="Matches found",  alpha=0.88)
    ax8.set_xticks(range(len(df_sg_k4)))
    ax8.set_xticklabels([p[:20] for p in df_sg_k4["pattern"]],rotation=20,ha="right",fontsize=8)
    ax8.set_ylabel("Count")
    ax8.set_yscale("log")
    ax8.set_title("Fig. 10: Subgraph Matching — Candidates vs. Matches", fontweight="bold")
    ax8.legend(fontsize=9)
    ax8.grid(True, alpha=0.3, axis="y")
 
    fig.suptitle("DVH-GQP Full Evaluation — ego-Facebook (SNAP)\n"
                 "Label Queries + BFS Reachability + Subgraph Matching | Neo4j AuraDB",
                 fontsize=14,fontweight="bold",y=0.995)
    path = os.path.join(out_dir,"dvhgqp_full_evaluation.png")
    fig.savefig(path, dpi=150, bbox_inches="tight")
    plt.close(fig)
    print(f"[Phase 4] Saved figures : {path}")
    return path
 
def make_comparison_plots(bfs_dvh, bfs_base, sg_dvh, sg_base, out_dir="outputs"):
    os.makedirs(out_dir, exist_ok=True)
    fig, axes = plt.subplots(2, 1, figsize=(10, 12))
    fig.suptitle("DVH-GQP vs. Baseline — ego-Facebook (SNAP)\n"
                 "Performance Comparison | Neo4j AuraDB",
                 fontsize=14, fontweight="bold")

    df_dvh_bfs  = pd.DataFrame(bfs_dvh)
    df_base_bfs = pd.DataFrame(bfs_base)
    df_dvh_sg   = pd.DataFrame(sg_dvh)
    df_base_sg  = pd.DataFrame(sg_base)

    # ── Fig 5: BFS total latency vs depth (high-degree node) ──
    ax = axes[0]
    for cls, color_d, color_b, ls_d, ls_b in [
        ("high_degree", COLORS["dvhgqp"],   COLORS["baseline"], "-",  "--"),
        ("mid_degree",  "#1D4ED8",           "#B91C1C",           "-",  "--"),
        ("low_degree",  "#60A5FA",           "#F87171",           "-",  "--"),
    ]:

        sub_d = df_dvh_bfs[(df_dvh_bfs["class"]==cls) & (df_dvh_bfs["k"]==4)].sort_values("depth")
        sub_b = df_base_bfs[(df_base_bfs["class"]==cls) & (df_base_bfs["k"]==4)].sort_values("depth")
        deg   = sub_d.iloc[0]["start_degree"] if not sub_d.empty else "?"
        if not sub_d.empty:
            ax.plot(sub_d["depth"], sub_d["t_total_ms"], "o"+ls_d, lw=2,
                    color=color_d, label=f"DVH-GQP {cls} (deg={deg})")
        if not sub_b.empty:
            ax.plot(sub_b["depth"], sub_b["t_total_ms"], "s"+ls_b, lw=2,
                    color=color_b, label=f"Baseline {cls}")
    ax.set_xlabel("BFS Depth D"); ax.set_ylabel("Total Latency (ms)")
    ax.set_title("Fig. 5: BFS Reachability — DVH-GQP vs. Baseline", fontweight="bold")
    ax.set_xticks([1,2,3]); ax.legend(fontsize=7); ax.grid(True, alpha=0.3)

    # ── Fig 6: Subgraph matching total latency ──
    ax = axes[1]
    x  = np.arange(len(df_dvh_sg)); w = 0.35
    ax.bar(x - w/2, df_dvh_sg["t_total_ms"],  w,
           label="DVH-GQP",  color=COLORS["dvhgqp"],   alpha=0.88)
    ax.bar(x + w/2, df_base_sg["t_total_ms"], w,
           label="Baseline", color=COLORS["baseline"],  alpha=0.88)
    ax.set_xticks(x)
    ax.set_xticklabels([p[:20] for p in df_dvh_sg["pattern"]],
                       rotation=18, ha="right", fontsize=8)
    ax.set_ylabel("Total Latency (ms)")
    ax.set_title("Fig. 6: Subgraph Matching — DVH-GQP vs. Baseline", fontweight="bold")
    ax.legend(fontsize=9); ax.grid(True, alpha=0.3, axis="y")

    plt.tight_layout()
    path = os.path.join(out_dir, "dvhgqp_vs_baseline_comparison.png")
    fig.savefig(path, dpi=150, bbox_inches="tight"); plt.close(fig)
    print(f"[Output] Saved: {path}")
    return path

# ── Main ─────────────────────────────────────────────────
def main():
    print("="*60)
    print("  DVH-GQP - Label + BFS + Subgraph Matching")
    print("="*60)
 
    download_snap()
    nodes, edges = load_snap_graph()
    node_label, edge_label = assign_labels(nodes, edges)
    degree = {}
    for u, v in edges:
        degree[u] = degree.get(u, 0) + 1
        degree[v] = degree.get(v, 0) + 1
 
    K  = keygen()
    Ks = keygen()
    Ke = keygen()
    print("[Keys] K, Ks, Ke generated")
 
    enc_nodes, enc_edges, enc_adj, dsse_index, hist, adj_plain, stats = phase1_encrypt(nodes, edges, node_label, edge_label, K, Ks, Ke)
 
    stats["label_breakdown"] = {}
    for w, real_ids in hist.items():
        r = len(real_ids)
        p = pad_size(r)
        stats["label_breakdown"][w] = {"real":r, "dummy":p-r, "p_r":p, "overhead_pct":round((p-r)/r*100,1)}
 
    print(f"[Phase 2] Connecting to Neo4j: {CONFIG['NEO4J_URI']}")
    driver = GraphDatabase.driver(CONFIG["NEO4J_URI"], auth = (CONFIG["NEO4J_USERNAME"], CONFIG["NEO4J_PASSWORD"]))
    driver.verify_connectivity()
    print("          Connection verified.")
    phase2_load_neo4j(driver, enc_nodes, enc_edges, enc_adj)
 
    label_results = run_label_benchmark(driver, dsse_index, Ks, Ke, K, hist)
    bfs_dvh,  bfs_base = run_bfs_benchmark(driver, K, adj_plain, node_label, degree)
    sg_dvh,   sg_base  = run_subgraph_benchmark(driver, K, adj_plain, node_label)
    driver.close()
 
    print("\n[Phase 4] Generating plots")
    make_evaluation_plots(label_results, bfs_dvh, sg_dvh, stats)

    print("="*60)
    print("  DVH-GQP vs. Baseline — Performance Comparison")
    print("  ego-Facebook | Neo4j AuraDB")
    print("="*60)
    make_comparison_plots(bfs_dvh, bfs_base, sg_dvh, sg_base)
 
    print("\n Complete. Outputs in outputs/")
    print("  dvhgqp_full_evaluation.png")
    print("  dvhgqp_vs_baseline_comparison.png")

if __name__ == "__main__":
    main()