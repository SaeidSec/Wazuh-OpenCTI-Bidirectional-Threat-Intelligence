# Wazuh-OpenCTI-Bidirectional-Threat-Intelligence
Endpoint telemetry is decoded by Wazuh, selected alerts are enriched live through OpenCTI's GraphQL API, eligible direct indicator matches create a STIX sighting, and the enriched event is re-injected for rule evaluation, dashboard visibility and optional Telegram notification.
