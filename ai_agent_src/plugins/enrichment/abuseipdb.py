from .base import EnrichmentPlugin


class AbuseIPDBPlugin(EnrichmentPlugin):
    name = "abuseipdb"
    required_env = ["ABUSEIPDB_API_KEY"]

    async def enrich(self, alert: dict) -> dict:
        # Enrichment already arrives pre-populated in alert fields:
        # ip_abuse_score, ip_is_tor, ip_total_reports — set by upstream SOAR pipeline.
        # Active IP lookups via ABUSEIPDB_API_KEY can be added here.
        return {}
