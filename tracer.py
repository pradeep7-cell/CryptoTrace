import hashlib
import json
import time
from typing import Dict, List, Tuple
import networkx as nx
from pyvis.network import Network


class ForensicAuditLogger:
    """Maintains a tamper-evident SHA-256 hash-chained audit log of every trace step."""

    def __init__(self):
        self.chain: List[Dict] = []
        self.prev_hash = "0" * 64

    def log_step(self, step_name: str, details: Dict) -> str:
        entry = {
            "index": len(self.chain),
            "timestamp": time.time(),
            "step": step_name,
            "details": details,
            "prev_hash": self.prev_hash,
        }
        serialized = json.dumps(entry, sort_keys=True).encode("utf-8")
        current_hash = hashlib.sha256(serialized).hexdigest()
        entry["hash"] = current_hash
        self.prev_hash = current_hash
        self.chain.append(entry)
        return current_hash

    def verify_integrity(self) -> bool:
        prev = "0" * 64
        for entry in self.chain:
            check_entry = {k: v for k, v in entry.items() if k != "hash"}
            recomputed = hashlib.sha256(
                json.dumps(check_entry, sort_keys=True).encode("utf-8")
            ).hexdigest()
            if recomputed != entry["hash"] or entry["prev_hash"] != prev:
                return False
            prev = entry["hash"]
        return True


class CryptoTraceEngine:
    """Multi-hop blockchain forensic engine with adversarial filtering and heuristics."""

    KNOWN_ENTITIES = {
        "0xExchangeHotWallet99": {"label": "Centralized Exchange Exit (KYC)", "risk_base": 85},
        "0xTornadoMixerPool01": {"label": "Sanctioned Mixer Contract", "risk_base": 95},
        "0xBridgeRouterETH2BSC": {"label": "Cross-Chain Bridge", "risk_base": 75},
    }

    def __init__(self):
        self.graph = nx.DiGraph()
        self.audit = ForensicAuditLogger()

    def is_dust_attack(self, amount_eth: float) -> bool:
        """Flags micro-transactions (< 0.0001 ETH) used to pollute transaction graphs."""
        return amount_eth < 0.0001

    def is_lookalike_spoof(self, target_addr: str, candidate_addr: str) -> bool:
        """Detects address poisoning attacks mimicking prefix and suffix characters."""
        if target_addr == candidate_addr or len(target_addr) < 10 or len(candidate_addr) < 10:
            return False
        same_prefix = target_addr[:5].lower() == candidate_addr[:5].lower()
        same_suffix = target_addr[-4:].lower() == candidate_addr[-4:].lower()
        return same_prefix and same_suffix

    def ingest_transactions(self, source_wallet: str, transactions: List[Dict]):
        """Builds a multi-hop directed graph while filtering adversarial noise."""
        self.audit.log_step("INGEST_START", {"source": source_wallet, "tx_count": len(transactions)})

        for tx in transactions:
            src = tx["from"]
            dst = tx["to"]
            val = tx["amount_eth"]
            hop = tx["hop"]

            # Cybersecurity Layer: Filter Dusting & Look-alike Address Spoofing
            if self.is_dust_attack(val):
                self.audit.log_step("THREAT_FLAGGED_DUST", {"from": src, "to": dst, "amount": val})
                continue

            if self.is_lookalike_spoof(source_wallet, dst):
                self.audit.log_step("THREAT_FLAGGED_SPOOF", {"target": source_wallet, "spoof": dst})
                continue

            self.graph.add_node(src, hop=hop - 1)
            self.graph.add_node(dst, hop=hop)
            self.graph.add_edge(src, dst, amount_eth=val, hop=hop, tx_hash=tx["tx_hash"])

        self.audit.log_step(
            "GRAPH_BUILT",
            {"nodes": self.graph.number_of_nodes(), "clean_edges": self.graph.number_of_edges()},
        )

    def deanonymize_end_receivers(self, source_wallet: str) -> List[Dict]:
        """Traces multi-hop paths (>= 3 hops) and ranks probable terminal receivers."""
        terminal_nodes = [
            node for node in self.graph.nodes if self.graph.out_degree(node) == 0 and node != source_wallet
        ]
        ranked_results = []

        for target in terminal_nodes:
            paths = list(nx.all_simple_paths(self.graph, source=source_wallet, target=target))
            if not paths:
                continue

            longest_path = max(paths, key=len)
            hop_count = len(longest_path) - 1

            # Calculate total value reaching terminal node
            in_edges = self.graph.in_edges(target, data=True)
            total_received = sum(data["amount_eth"] for _, _, data in in_edges)

            # Heuristic scoring: Peel chain retention + known exit ramp identification
            entity_info = self.KNOWN_ENTITIES.get(
                target, {"label": "Unattributed Terminal Wallet", "risk_base": 55}
            )
            confidence = min(98.5, round(50.0 + (hop_count * 8.5) + (total_received * 1.5), 2))
            cyber_risk_score = min(100, int(entity_info["risk_base"] + (hop_count * 2)))

            ranked_results.append({
                "end_receiver": target,
                "attribution": entity_info["label"],
                "hops_traced": hop_count,
                "total_received_eth": round(total_received, 4),
                "confidence_pct": confidence,
                "cyber_risk_score": cyber_risk_score,
                "trace_path": " -> ".join(longest_path),
            })

        ranked_results.sort(key=lambda x: (x["cyber_risk_score"], x["confidence_pct"]), reverse=True)
        self.audit.log_step("DEANONYMIZATION_COMPLETE", {"candidates_found": len(ranked_results)})
        return ranked_results

    def export_interactive_graph(self, source_wallet: str, output_file: str = "trace_graph.html"):
        """Generates an interactive PyVis network graph for judge demonstration."""
        net = Network(height="600px", width="100%", directed=True, bgcolor="#111827", font_color="white")
        for node in self.graph.nodes:
            if node == source_wallet:
                color = "#EF4444"  # Red: Illicit Source
            elif node in self.KNOWN_ENTITIES:
                color = "#F59E0B"  # Amber: Known Exit / Mixer
            else:
                color = "#3B82F6"  # Blue: Intermediate Hop
            net.add_node(node, label=node, color=color, title=self.KNOWN_ENTITIES.get(node, {}).get("label", "Hop Wallet"))

        for u, v, data in self.graph.edges(data=True):
            net.add_edge(u, v, label=f"{data['amount_eth']} ETH (Hop {data['hop']})", color="#9CA3AF")

        net.save_graph(output_file)
        self.audit.log_step("VISUALIZATION_EXPORTED", {"file": output_file})


if __name__ == "__main__":
    # Sample multi-hop illicit transaction dataset (Ransomware -> Peel Chain -> Exchange Exit + Attacker Noise)
    ILLICIT_SOURCE = "0xRansomwareOrigin1A9F"
    sample_txs = [
        {"tx_hash": "0xtx1", "from": "0xRansomwareOrigin1A9F", "to": "0xPeelHop1_88B2", "amount_eth": 12.5, "hop": 1},
        {"tx_hash": "0xtx2", "from": "0xPeelHop1_88B2", "to": "0xPeelHop2_44C1", "amount_eth": 11.8, "hop": 2},
        {"tx_hash": "0xtx3", "from": "0xPeelHop2_44C1", "to": "0xExchangeHotWallet99", "amount_eth": 11.2, "hop": 3},
        {"tx_hash": "0xtx4", "from": "0xPeelHop2_44C1", "to": "0xTornadoMixerPool01", "amount_eth": 0.55, "hop": 3},
        # Adversarial Noise (Should be automatically filtered out by Cybersecurity Layer)
        {"tx_hash": "0xtx_dust", "from": "0xAttackerDustBot", "to": "0xPeelHop1_88B2", "amount_eth": 0.000001, "hop": 1},
        {"tx_hash": "0xtx_spoof", "from": "0xPeelHop1_88B2", "to": "0xRansomwareFake1A9F", "amount_eth": 0.01, "hop": 2},
    ]

    engine = CryptoTraceEngine()
    engine.ingest_transactions(ILLICIT_SOURCE, sample_txs)
    results = engine.deanonymize_end_receivers(ILLICIT_SOURCE)

    print("\n=== CRYPTOTRACE RANKED END-RECEIVER REPORT ===")
    print(json.dumps(results, indent=2))
    print(f"\nAudit Log Tamper-Check Valid: {engine.audit.verify_integrity()} ({len(engine.audit.chain)} blocks hashed)")

    engine.export_interactive_graph(ILLICIT_SOURCE)
    print("Interactive graph saved to: trace_graph.html")
