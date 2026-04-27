# DVH-GQP: Dynamic Volume-Hiding Graph Query Processing

A privacy-preserving graph query system that encrypts graph data using AES-GCM, stores it in Neo4j AuraDB, and supports secure queries via a DSSE (Dynamic Symmetric Searchable Encryption) label index, ORAM-padded BFS traversal, and subgraph matching — all with simulated AWS Nitro Enclave (TEE) and Apache Spark execution costs.

---

## Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Features](#features)
- [Requirements](#requirements)
- [Installation](#installation)
- [Configuration](#configuration)
- [Usage](#usage)
  - [Demo Web App](#demo-web-app)
  - [Full Evaluation](#full-evaluation)
- [Query Types](#query-types)
- [Security Model](#security-model)
- [Dataset](#dataset)
- [Project Structure](#project-structure)
- [Evaluation Output](#evaluation-output)

---

## Overview

DVH-GQP enables graph queries over **fully encrypted graph data** without exposing node labels, edge relationships, or adjacency information to the storage backend. The system is designed around three core primitives:

| Primitive | Purpose |
|---|---|
| **AES-GCM** | Encrypts nodes, edges, and adjacency lists |
| **DSSE Index** | Enables label-based lookups without revealing the label |
| **Selective ORAM** | Pads fetch sizes to hide access patterns from Neo4j |

Simulated costs for **AWS Nitro Enclaves (TEE)** and **Apache Spark** are included to reflect realistic distributed deployment overhead.

---

## Architecture

```
  Client (Python)
      │
      ├── Phase 1: Encrypt graph (AES-GCM) + Build DSSE index
      │
      ├── Phase 2: Load encrypted nodes + edges into Neo4j AuraDB
      │
      └── Phase 3: Query engine
            ├── Label query   → DSSE lookup + TEE decrypt
            ├── BFS query     → ORAM-padded fetch + Spark parallelism
            └── Subgraph      → Candidate fetch + pattern matching
```

---

## Features

- **AES-256-GCM encryption** for all nodes, edges, and adjacency lists
- **DSSE label index** with PRF-hashed keys and 10% dummy-entry padding
- **ORAM-padded BFS** — fetches P(r) = r + ⌈0.10·r⌉ blocks to hide true query size
- **Subgraph pattern matching** over encrypted graphs (e.g., `Influencer -[FOLLOWS]-> Person`)
- **Neo4j AuraDB** backend with batch ingestion and indexed lookup
- **Simulated TEE costs** based on AWS Nitro Enclave attestation benchmarks
- **Simulated Spark costs** based on AWS EMR scheduling and shuffle benchmarks
- **Flask web demo** for interactive dataset loading and querying
- **Matplotlib evaluation plots** (10 figures) comparing DVH-GQP vs. baseline

---

## Requirements

- Python 3.8+
- Neo4j AuraDB instance (for evaluation)

### Python Packages

```bash
pip install flask pycryptodome networkx neo4j numpy pandas matplotlib python-dotenv
```

---

## Installation

```bash
git clone https://github.com/your-org/dvhgqp.git
cd dvhgqp
pip install flask pycryptodome networkx neo4j numpy pandas matplotlib python-dotenv
```

---

## Configuration

Create a `.env` file in the project root for the evaluation script:

```env
NEO4J_URI=neo4j+s://<your-instance>.databases.neo4j.io
NEO4J_USERNAME=neo4j
NEO4J_PASSWORD=your_password
BATCH_SIZE=500
REPEAT=10
```

> The demo web app (`DVHGQP-Demo.py`) does **not** require Neo4j — it operates entirely in memory.

---

## Usage

### Demo Web App

Runs a local Flask server with an interactive UI for loading any SNAP-format edge-list dataset and running natural-language queries.

```bash
pip install flask pycryptodome
python DVHGQP-Demo.py
```

Open [http://localhost:5000](http://localhost:5000) in your browser.

**Steps:**
1. Paste a dataset URL (`.txt` or `.gz` edge-list format) from [SNAP](https://snap.stanford.edu/data)
2. Click **Load & Encrypt** — the graph is downloaded, encrypted, and indexed in memory
3. Use the query chips or type a natural-language query

### Full Evaluation

Runs the complete benchmark against Neo4j AuraDB using the ego-Facebook dataset (SNAP).

```bash
python DVHGQP-Evaluation.py
```

This will:
1. Download `facebook_combined.txt.gz` from SNAP (4,039 nodes, 88,234 edges)
2. Encrypt the graph and build the DSSE + adjacency index
3. Load encrypted data into Neo4j AuraDB
4. Run label queries, BFS reachability, and subgraph matching benchmarks
5. Generate two output figures in `outputs/`

---

## Query Types

### Natural-Language Queries (Demo)

| Example Query | Type |
|---|---|
| `How many nodes?` | Node count |
| `How many edges?` | Edge count |
| `How many friends does node 0 have?` | Degree / adjacency |
| `What label is node 0?` | Node label lookup |
| `How many Influencer nodes?` | DSSE label count |
| `BFS from node 0 depth 2` | BFS reachability |
| `Can node 0 reach node 500?` | Reachability check |
| `Find Influencer FOLLOWS Person` | Subgraph matching |

### Node Labels (auto-assigned by degree percentile)

| Label | Degree Threshold |
|---|---|
| `Influencer` | Top 5% (≥ p95) |
| `Community` | Top 25% (≥ p75) |
| `Person` | Top 50% (≥ p50) |
| `Organization` | Top 75% (≥ p25) |
| `Bot` | Bottom 25% |

### Edge Labels

`FRIEND`, `FOLLOWS`, `MEMBER_OF`, `INTERACTS` — assigned deterministically by `(u + v) % 4`.

---

## Security Model

| Component | Mechanism |
|---|---|
| Node/edge content | AES-256-GCM encrypted with key `K` |
| Adjacency lists | AES-256-GCM encrypted with key `K`, stored per node |
| DSSE index keys | PRF(Ks, label) — Neo4j never sees plaintext labels |
| DSSE entries | AES-256-GCM encrypted with key `Ke` + 10% dummy padding |
| Access pattern | ORAM-style: always fetch P(r) blocks, not exactly r |
| TEE simulation | AWS Nitro Enclave: 68ms attestation + 0.5µs/entry AES-NI |

Keys `K`, `Ks`, `Ke` are 256-bit random keys generated at setup and held client-side only.

---

## Dataset

The evaluation uses the **ego-Facebook** dataset from Stanford SNAP:

- **URL:** https://snap.stanford.edu/data/facebook_combined.txt.gz
- **Nodes:** 4,039 | **Edges:** 88,234
- **Format:** space-separated edge list (`u v` per line, `#` for comments)

Any SNAP-format edge-list can be used with the demo web app.

---

## Project Structure

```
dvhgqp/
├── DVHGQP-Demo.py          # Flask web demo (in-memory, no Neo4j required)
├── DVHGQP-Evaluation.py    # Full benchmark with Neo4j AuraDB + plots
├── .env                    # Neo4j credentials (create this yourself)
├── outputs/                # Generated evaluation figures
│   ├── dvhgqp_full_evaluation.png
│   └── dvhgqp_vs_baseline_comparison.png
└── README.md
```

---

## Evaluation Output

The evaluation generates two PNG files in `outputs/`:

**`dvhgqp_full_evaluation.png`** — 10 figures covering:
- Label query latency breakdown (TEE / Neo4j / Spark)
- DSSE padding overhead per label
- Storage overhead ratio
- BFS reachability latency vs. depth (high / mid / low degree nodes)
- BFS nodes visited vs. depth
- BFS latency vs. Spark parallelism `k`
- BFS latency component breakdown
- Subgraph matching latency by pattern
- Subgraph candidates vs. matches found

**`dvhgqp_vs_baseline_comparison.png`** — DVH-GQP vs. unpadded baseline:
- BFS total latency comparison
- Subgraph matching total latency comparison
