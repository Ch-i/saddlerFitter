"""saddlerFitter — a code-quality and security platform that fits the saddle to the
horse and rider.

saddlerFitter is a harness: a team of LLM agents that audit code by cross-family
consensus, gate commits, and surface findings through a human-in-the-loop IRC hub —
gated so nothing irreversible lands without a human approval. Two companion parts give
it memory and let it grow:

- **knowledge** (`saddlerfitter.knowledge`) — the *memory*: a versioned rule catalog
  (CWE/OWASP/UK frameworks) that drives detection and phrases every recommendation, so a
  finding is citable rather than an opinion.
- **research** (`saddlerfitter.research`) — the *learning loop*: an ingest database fed
  by autoresearch and a scheduled watch over the latest CVEs and vulnerability
  disclosures, so the platform grows over time and signals → triages → tickets new risk.

The model is a swappable component; the harness is the product.
"""
__version__ = "0.2.0"
