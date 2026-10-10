# System Architecture

This diagram shows the configured Wazuh-to-OpenCTI enrichment and sighting loop, plus optional Telegram notification. Dashed connections are deployment configuration or standard Wazuh outputs not implemented by this repository.

```mermaid
flowchart LR
    subgraph ThreatIntel[Threat intelligence sources]
        Feeds[External feeds and providers<br/>selected by deployment]
        Connectors[OpenCTI connectors]
        Feeds -->|feed ingestion| Connectors
    end

    subgraph OpenCTI[OpenCTI deployment]
        Platform[OpenCTI platform<br/>UI and GraphQL API]
        Indicators[Knowledge graph<br/>indicators and observables]
        Search[(Search backend)]
        Redis[(Redis cache)]
        Rabbit[(RabbitMQ broker)]
        Storage[(MinIO or S3 storage)]
        Connectors -->|ingested STIX intelligence| Platform
        Platform <--> Indicators
        Platform <--> Search
        Platform <--> Redis
        Platform <--> Rabbit
        Platform <--> Storage
    end

    subgraph Endpoints[Monitored endpoints]
        Win[Windows telemetry<br/>Sysmon event channel<br/>FIM and registry]
        Linux[Linux telemetry<br/>auditd log<br/>FIM]
        Other[Optional collected sources<br/>IDS or Packetbeat DNS<br/>osquery, SSH, firewall]
        WinAgent[Wazuh agent]
        LinuxAgent[Wazuh agent]
        OtherAgent[Wazuh agent or manager input]
        Win --> WinAgent
        Linux --> LinuxAgent
        Other --> OtherAgent
    end

    subgraph Manager[Wazuh manager]
        Analysisd[analysisd<br/>decoders and rules]
        Integratord[integratord<br/>group-filtered alert dispatch]
        OpenCTIScript[custom-opencti.py<br/>IOC extraction, GraphQL lookup<br/>score and revoked filtering]
        Queue[Local Unix datagram queue]
        State[(Local state file<br/>sighting dedupe and identity cache)]
        TelegramScript[custom-telegram.py<br/>optional notifier]
        Analysisd -->|selected source alert as JSON| Integratord
        Integratord -->|configured alert groups| OpenCTIScript
        OpenCTIScript -->|enriched opencti event or error| Queue
        Queue -->|agent-attributed event reinjection| Analysisd
        OpenCTIScript <--> |dedupe and cached identity| State
        Integratord -->|opencti_alert or opencti_high<br/>and level 10+| TelegramScript
    end

    WinAgent -->|agent telemetry| Analysisd
    LinuxAgent -->|agent telemetry| Analysisd
    OtherAgent -.->|when enabled and collected| Analysisd

    OpenCTIScript -->|HTTPS or HTTP GraphQL IOC query| Platform
    Platform -->|indicator, observable and relationship results| OpenCTIScript
    OpenCTIScript -->|GraphQL STIX sighting mutation<br/>eligible direct indicator matches only| Platform

    subgraph Outputs[Alert destinations]
        Indexer[Wazuh indexer]
        Dashboard[Wazuh dashboard]
        TelegramAPI[Telegram Bot API]
        Chat[Telegram chat]
        Indexer -->|search and visualization| Dashboard
        TelegramAPI -->|message| Chat
    end

    Analysisd -.->|standard Wazuh alert output<br/>transport not configured here| Indexer
    TelegramScript -->|HTTPS sendMessage| TelegramAPI

    subgraph RepoConfig[Repository deployment configuration]
        AgentConfig[agent-groups configs<br/>Windows and Linux]
        RuleConfig[Wazuh rule XML<br/>source rules and OpenCTI rules]
        IntegrationConfig[ossec.conf integration blocks<br/>OpenCTI and optional Telegram]
    end
    AgentConfig -.->|shared agent configuration| WinAgent
    AgentConfig -.->|shared agent configuration| LinuxAgent
    RuleConfig -.->|installed manager rules| Analysisd
    IntegrationConfig -.->|integration names and filters| Integratord

    classDef optional stroke-dasharray: 5 5;
    class Other,OtherAgent,TelegramScript,TelegramAPI,Chat optional;
```

## Flow Notes

- OpenCTI connectors ingest deployment-selected threat feeds into the OpenCTI platform. The repository does not provision specific feed connectors.
- Windows and Linux Wazuh agents forward telemetry to the manager. The integration also supports IDS/Packetbeat DNS, osquery, and generic network alert fields when those sources are collected and their rule groups are routed to it.
- The OpenCTI integration queries indicators and observables live through GraphQL; it does not synchronize a local IOC database. Enriched events are written to the manager's local queue and reprocessed by `analysisd` with the originating agent attribution.
- The integration can write a STIX sighting for eligible direct indicator matches. Sightings are deduplicated per indicator and agent for the configured window (one hour by default). Filename and related-indicator matches do not create sightings.
- The optional Telegram integration receives qualifying OpenCTI alerts (groups `opencti_alert` or `opencti_high`, level 10 or above) and sends them through the Telegram Bot API.
- Wazuh indexer and dashboard are shown as the normal Wazuh alert destination. This repository does not configure the manager-to-indexer transport; its custom configuration is the OpenCTI and optional Telegram integrations.