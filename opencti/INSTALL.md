# OpenCTI — Installation & Core Dependencies

## 1. Hardware Requirements

For a standard production environment, it is highly recommended to use **SSD storage** to avoid performance bottlenecks in Elasticsearch.

| Component | Minimum (Lab/Testing) | Recommended (Small Prod) | Medium/Large Enterprise |
|---|---|---|---|
| **CPU** | 4 Cores | 8 Cores | 16+ Cores |
| **RAM** | 8 GB | 16 GB | 32 GB - 64 GB+ |
| **Storage** | 40 GB SSD | 128 GB SSD | 500 GB+ NVMe |

## 2. Software Prerequisites

OpenCTI is primarily designed to run in **Docker**, which is the easiest installation method.

- **Operating System:** Linux (Ubuntu 22.04 LTS or 24.04 LTS recommended). While it can run on Windows via WSL2, Linux is preferred for production.
- **Docker & Docker Compose:**
  - Docker Engine: v20.10+
  - Docker Compose: v2.20+
- **System Configuration (Critical):** Elasticsearch requires a specific memory map count to start.

Docker Installation:

```bash
# Add Docker's official GPG key:
sudo apt update
sudo apt install ca-certificates curl
sudo install -m 0755 -d /etc/apt/keyrings
sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
sudo chmod a+r /etc/apt/keyrings/docker.asc

# Add the repository to Apt sources:
sudo tee /etc/apt/sources.list.d/docker.sources <<EOF
Types: deb
URIs: https://download.docker.com/linux/ubuntu
Suites: $(. /etc/os-release && echo "${UBUNTU_CODENAME:-$VERSION_CODENAME}")
Components: stable
Signed-By: /etc/apt/keyrings/docker.asc
EOF

sudo apt update

sudo apt install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin -y
```

```bash
# Run this on your host machine
sudo sysctl -w vm.max_map_count=1048575
# To make it permanent, add it to /etc/sysctl.conf
```

## 3. Core Dependencies & Their Resource Share

OpenCTI is a "stack" of services. If you are deploying via Docker, these are the individual resource needs for the containers:

- **Elasticsearch (Database):** Uses the most RAM. Requires at least **4GB to 8GB** dedicated just to this service.
- **Redis (Cache):** Lightweight; needs about **512MB - 1GB**.
- **RabbitMQ (Broker):** Handles messaging between workers; needs **512MB - 1GB**.
- **MinIO / S3 (Storage):** Stores uploaded files and artifacts; needs **256MB+**.
- **OpenCTI Platform:** The UI and API; needs **2GB - 4GB**.
- **Workers:** Python processes that ingest data; need **256MB** each (start with 3 workers).

## 4. Network & Security Requirements

- **Ports:**
  - `8080`: Main UI/API (default).
  - `5672/15672`: RabbitMQ (internal/management).
  - `9200`: Elasticsearch (internal).
  - `9000/9001`: MinIO console and API.
- **Authentication:** You must generate a **UUID v4** for your `OPENCTI_ADMIN_TOKEN`.

## OpenCTI Installation

Docker helpers are available in the [Docker GitHub repository](https://github.com/OpenCTI-Platform/docker).

```bash
mkdir -p opencti
git clone https://github.com/OpenCTI-Platform/docker.git
cd docker
```

Once install the opencti package from docker and make sure that copy .env-sample to .env

```bash
ls -la --check name of the files:
cp .env.sample .env
```

ENV:

```bash
uuidgen --  OPENCTI_ADMIN_TOKEN,OPENCTI_HEALTHCHECK_ACCESS_KEY
openssl rand -base64 32 -- OPENCTI_ENCRYPTION_KEY
```

```bash
###########################
# DEPENDENCIES            #
###########################

MINIO_ROOT_USER=opencti
MINIO_ROOT_PASSWORD=
RABBITMQ_DEFAULT_USER=opencti
RABBITMQ_DEFAULT_PASS=
SMTP_HOSTNAME=localhost
OPENSEARCH_ADMIN_PASSWORD=
ELASTIC_MEMORY_SIZE=4G

###########################
# COMMON                  #
###########################

XTM_COMPOSER_ID=8215614c-7139-422e-b825-b20fd2a13a23
COMPOSE_PROJECT_NAME=xtm

###########################
# OPENCTI                 #
###########################

OPENCTI_HOST=10.10.30.53
OPENCTI_PORT=8080
OPENCTI_EXTERNAL_SCHEME=http
OPENCTI_ADMIN_EMAIL=admin@opencti.io
OPENCTI_ADMIN_PASSWORD=
OPENCTI_ADMIN_TOKEN=<uuidgen>
OPENCTI_HEALTHCHECK_ACCESS_KEY=<uuidgen>

###########################
# OPENCTI CONNECTORS      #
###########################

CONNECTOR_EXPORT_FILE_STIX_ID=dd817c8b-abae-460a-9ebc-97b1551e70e6
CONNECTOR_EXPORT_FILE_CSV_ID=7ba187fb-fde8-4063-92b5-c3da34060dd7
CONNECTOR_EXPORT_FILE_TXT_ID=ca715d9c-bd64-4351-91db-33a8d728a58b
CONNECTOR_IMPORT_FILE_STIX_ID=72327164-0b35-482b-b5d6-a5a3f76b845f
CONNECTOR_IMPORT_DOCUMENT_ID=c3970f8a-ce4b-4497-a381-20b7256f56f0
CONNECTOR_IMPORT_FILE_YARA_ID=7eb45b60-069b-4f7f-83a2-df4d6891d5ec
CONNECTOR_IMPORT_EXTERNAL_REFERENCE_ID=d52dcbc8-fa06-42c7-bbc2-044948c87024
CONNECTOR_ANALYSIS_ID=4dffd77c-ec11-4abe-bca7-fd997f79fa36

###########################
# OPENCTI DEFAULT DATA    #
###########################

CONNECTOR_OPENCTI_ID=dd010812-9027-4726-bf7b-4936979955ae
CONNECTOR_MITRE_ID=8307ea1e-9356-408c-a510-2d7f8b28a0e2

CONNECTOR_WAZUH_ID=2e4d2f0c-6a1a-4c9f-9b5e-2b7b0e6d9e11
```

```bash
Next save the file: start docker

docker compose up -d --build
```
