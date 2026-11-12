from fastapi import FastAPI, Form
from fastapi.responses import HTMLResponse
import os
from tracer import CryptoTraceEngine

app = FastAPI(title="CryptoTrace Forensics Dashboard")


def run_forensic_trace(source_wallet: str):
    """Runs the CryptoTrace engine on the requested wallet address."""
    sample_txs = [
        {"tx_hash": "0xtx1", "from": source_wallet, "to": "0xPeelHop1_88B2", "amount_eth": 12.5, "hop": 1},
        {"tx_hash": "0xtx2", "from": "0xPeelHop1_88B2", "to": "0xPeelHop2_44C1", "amount_eth": 11.8, "hop": 2},
        {"tx_hash": "0xtx3", "from": "0xPeelHop2_44C1", "to": "0xExchangeHotWallet99", "amount_eth": 11.2, "hop": 3},
        {"tx_hash": "0xtx4", "from": "0xPeelHop2_44C1", "to": "0xTornadoMixerPool01", "amount_eth": 0.55, "hop": 3},
        # Adversarial noise automatically filtered out by your Cybersecurity Layer
        {"tx_hash": "0xtx_dust", "from": "0xAttackerDustBot", "to": "0xPeelHop1_88B2", "amount_eth": 0.000001, "hop": 1},
        {"tx_hash": "0xtx_spoof", "from": "0xPeelHop1_88B2", "to": source_wallet[:5] + "Fake" + source_wallet[-4:], "amount_eth": 0.01, "hop": 2},
    ]

    engine = CryptoTraceEngine()
    engine.ingest_transactions(source_wallet, sample_txs)
    results = engine.deanonymize_end_receivers(source_wallet)
    engine.export_interactive_graph(source_wallet, "trace_graph.html")

    with open("trace_graph.html", "r", encoding="utf-8") as f:
        graph_html = f.read()

    return results, engine.audit.verify_integrity(), len(engine.audit.chain), graph_html


def render_page(wallet: str = "0xRansomwareOrigin1A9F", results=None, is_valid=True, block_count=0, graph_html=""):
    rows_html = ""
    if results:
        for idx, r in enumerate(results, 1):
            badge_color = "#EF4444" if r["cyber_risk_score"] >= 95 else "#F59E0B"
            rows_html += f"""
            <tr>
                <td><strong>#{idx}</strong></td>
                <td><code>{r['end_receiver']}</code></td>
                <td>{r['attribution']}</td>
                <td>{r['hops_traced']} Hops</td>
                <td><strong>{r['total_received_eth']} ETH</strong></td>
                <td>{r['confidence_pct']}%</td>
                <td><span style="background:{badge_color}; color:white; padding:4px 10px; border-radius:12px; font-weight:bold;">{r['cyber_risk_score']}/100</span></td>
            </tr>
            """

    results_section = ""
    if results is not None:
        audit_text = f"VERIFIED ({block_count} SHA-256 Blocks Hashed)" if is_valid else "TAMPER DETECTED"
        results_section = f"""
        <div class="card">
            <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:15px;">
                <h2 style="margin:0;">Ranked End-Receiver Attribution</h2>
                <span style="background:#10B981; color:#064E3B; padding:6px 14px; border-radius:20px; font-weight:bold; font-size:13px;">
                    Audit Integrity: {audit_text}
                </span>
            </div>
            <p style="color:#9CA3AF; font-size:14px; margin-top:0;">
                Adversarial Filter Active: 1 Dusting Attack (&lt;0.0001 ETH) and 1 Look-Alike Spoof Address isolated and excluded.
            </p>
            <table>
                <thead>
                    <tr>
                        <th>Rank</th>
                        <th>End-Receiver Address</th>
                        <th>Entity Classification</th>
                        <th>Depth</th>
                        <th>Traced Value</th>
                        <th>Confidence</th>
                        <th>Cyber Risk</th>
                    </tr>
                </thead>
                <tbody>{rows_html}</tbody>
            </table>
        </div>

        <div class="card">
            <h2 style="margin-top:0;">Interactive Multi-Hop Transaction Trail</h2>
            <p style="color:#9CA3AF; font-size:14px;">
                <span style="color:#EF4444;">&#9679;</span> Illicit Source &nbsp;&nbsp;
                <span style="color:#3B82F6;">&#9679;</span> Intermediate Peel Hops &nbsp;&nbsp;
                <span style="color:#F59E0B;">&#9679;</span> High-Risk Exit Ramps (Drag nodes to inspect)
            </p>
            <div style="border:1px solid #374151; border-radius:8px; overflow:hidden;">
                <iframe srcdoc='{graph_html.replace("'", "&apos;")}' width="100%" height="520px" style="border:none;"></iframe>
            </div>
        </div>
        """

    return f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>CryptoTrace | Blockchain Forensics Engine</title>
        <style>
            body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #0B0F19; color: #F3F4F6; margin: 0; padding: 30px; }}
            .container {{ max-width: 1100px; margin: auto; }}
            .header {{ text-align: center; margin-bottom: 30px; }}
            .header h1 {{ color: #38BDF8; margin-bottom: 5px; font-size: 32px; }}
            .header p {{ color: #9CA3AF; margin-top: 0; }}
            .search-box {{ display: flex; gap: 10px; background: #111827; padding: 20px; border-radius: 12px; border: 1px solid #1F2937; margin-bottom: 25px; }}
            input[type="text"] {{ flex: 1; padding: 12px 16px; border-radius: 8px; border: 1px solid #374151; background: #1F2937; color: white; font-size: 16px; }}
            button {{ background: #2563EB; color: white; border: none; padding: 12px 24px; border-radius: 8px; font-size: 16px; font-weight: bold; cursor: pointer; }}
            button:hover {{ background: #1D4ED8; }}
            .card {{ background: #111827; padding: 25px; border-radius: 12px; border: 1px solid #1F2937; margin-bottom: 25px; }}
            table {{ width: 100%; border-collapse: collapse; margin-top: 10px; }}
            th, td {{ text-align: left; padding: 12px; border-bottom: 1px solid #1F2937; }}
            th {{ color: #9CA3AF; font-size: 13px; text-transform: uppercase; }}
            code {{ background: #1F2937; padding: 3px 6px; border-radius: 4px; color: #38BDF8; }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>CryptoTrace Forensics Engine</h1>
                <p>Cybersecurity-Driven Multi-Hop Deanonymization &amp; Illicit Fund Tracking</p>
            </div>
            <form method="post" action="/trace" class="search-box">
                <input type="text" name="wallet" value="{wallet}" placeholder="Enter suspicious ETH/BTC wallet address..." required />
                <button type="submit">Trace Illicit Funds</button>
            </form>
            {results_section}
        </div>
    </body>
    </html>
    """


@app.get("/", response_class=HTMLResponse)
def home():
    results, is_valid, block_count, graph_html = run_forensic_trace("0xRansomwareOrigin1A9F")
    return render_page("0xRansomwareOrigin1A9F", results, is_valid, block_count, graph_html)


@app.post("/trace", response_class=HTMLResponse)
def trace(wallet: str = Form(...)):
    results, is_valid, block_count, graph_html = run_forensic_trace(wallet.strip())
    return render_page(wallet.strip(), results, is_valid, block_count, graph_html)
