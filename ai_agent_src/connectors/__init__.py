from .wazuh   import WazuhConnector
from .elastic import ElasticConnector
from .splunk  import SplunkConnector
from .qradar  import QRadarConnector
from .generic import GenericConnector
from .base    import SIEMConnector

CONNECTOR_REGISTRY: dict[str, SIEMConnector] = {
    "wazuh":   WazuhConnector(),
    "elastic": ElasticConnector(),
    "splunk":  SplunkConnector(),
    "qradar":  QRadarConnector(),
    "generic": GenericConnector(),
}
