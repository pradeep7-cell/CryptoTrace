# CryptoTrace
**Track:** Blockchain & Cybersecurity (PS 1)  
**Tagline:** A Cybersecurity-Driven Blockchain Forensics Engine for Deanonymizing End Receivers of Illicit Crypto Transactions.

---

## 1. Executive Summary & Problem Statement
* **The Challenge:** Cybercriminals, ransomware operators, and money launderers exploit pseudonymous public blockchains (Bitcoin/Ethereum) using evasion techniques like mixers/tumblers, peel chains, chain-hopping bridges, and smurfing wallets to hide the trail of illicit funds.
* **The Gap:** Standard block explorers only display raw transaction data without risk intelligence or resistance to adversarial attacks such as dusting or look-alike address spoofing.
* **Our Solution:** **CryptoTrace** is a security-first forensic engine that ingests multi-hop blockchain data, filters out attacker-injected noise, applies deanonymization heuristics, and outputs a ranked list of probable end-receiver entities with verifiable confidence and cyber-risk scores.

---

## 2. System Architecture & Workflow
The system processes a suspicious wallet address or transaction hash through five sequential pipeline layers:

1. **Data Ingestion Layer:** Fetches multi-hop transaction histories via public blockchain APIs (Etherscan, Blockchair, RPC nodes) while validating API response integrity and rate limits.
2. **Cybersecurity & Threat Layer (Pre-filtering):** Scans incoming edges to flag and isolate adversarial artifacts, including dusting attacks, decoy transactions, and look-alike address spoofing.
3. **Graph Construction Engine:** Builds a directed multi-hop transaction graph (`NetworkX` / `Neo4j`) storing transaction values, timestamps, and hop depth as node and edge attributes.
4. **Deanonymization & Heuristic Module:** Applies behavioral clustering (common-input ownership, address reuse), peel-chain detection, mixer fan-in/fan-out pattern matching, and known entity labeling.
5. **Risk Scoring, Audit & Visualization:** Computes a composite cyber-risk score (`scikit-learn` + custom rules), logs the forensic trace into a SHA-256 hash-chained audit log, and renders an interactive trail graph (`PyVis` / `Plotly`).

---

## 3. Core Features & Deliverables

| Deliverable Component | Implementation Details |
| :--- | :--- |
| **Input Interface** | REST API (`FastAPI`) and web dashboard accepting a target BTC/ETH wallet address or transaction hash with configurable hop depth (>= 3 hops). |
| **Trace Graph** | Directed multigraph modeling fund flows across hops, annotated with timestamps, crypto/USD amounts, and heuristic tags. |
| **Heuristic Engine** | Automated modules for peel-chain tracing, mixer signature detection, address clustering, and cross-chain bridge correlation. |
| **Cybersecurity Module** | Detects zero-value/micro-value dusting attacks, flags look-alike address prefixes/suffixes, and generates a tamper-evident SHA-256 hash-chained audit log. |
| **Ranked Output** | JSON and UI table ranking Top-N probable end-receiver addresses with confidence percentages, cyber-risk scores (0–100), and human-readable reasoning. |
| **Visualization** | Interactive network graph highlighting illicit source nodes, intermediate hops, flagged decoys, and high-risk exit ramps. |

---

## 4. Technical Stack
* **Blockchain Data Sources:** Ethereum/Bitcoin RPC, Etherscan API, Blockchair API, OFAC Sanctioned Address Lists.
* **Backend & API:** Python 3.10+, FastAPI, Uvicorn.
* **Graph Processing:** NetworkX (in-memory prototyping), Neo4j (persistent graph storage).
* **Security & ML:** `hashlib` (SHA-256 hash-chained forensic logs), `scikit-learn` (anomaly/risk scoring), custom heuristic rule engine.
* **Frontend & Visualization:** React.js (Dashboard UI), PyVis / Plotly / Neo4j Bloom (Interactive graph rendering).

---

## 5. Setup & Execution Guide
```bash
# 1. Clone the repository
git clone https://github.com
cd CryptoTrace

# 2. Install backend dependencies
pip install -r requirements.txt

# 3. Configure environment variables (.env)
ETHERSCAN_API_KEY=your_api_key_here
BLOCKCHAIR_API_KEY=your_api_key_here

# 4. Run the FastAPI server
uvicorn app.main:app --reload
```
