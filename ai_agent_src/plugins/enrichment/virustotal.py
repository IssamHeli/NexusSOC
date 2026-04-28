from .base import EnrichmentPlugin


class VirusTotalPlugin(EnrichmentPlugin):
    name = "virustotal"
    required_env = ["VT_API_KEY"]

    async def enrich(self, alert: dict) -> dict:
        # Enrichment already arrives pre-populated in alert fields:
        # vt_malicious, vt_total, vt_names — set by upstream SOAR pipeline.
        # Active hash/URL lookups via VT_API_KEY can be added here.
        return {}
