### 1. Dedicated System Account

Select an unused numeric ID on your host:

```bash
APP_UID=<CHOSEN_UID>

getent passwd ${APP_UID}
getent group ${APP_UID}
```

Create a dedicated system user and group without shell access:

```bash
sudo useradd -m -d /home/reconsr -s /usr/sbin/nologin -u ${APP_UID} -U reconsr
```

### 2. Configure Permissions & Deployment Files

Create the deployment directory and fetch configuration files:

```bash
sudo mkdir -p /home/reconsr
sudo chown root:reconsr /home/reconsr
sudo chmod 0750 /home/reconsr
```

```bash
REPO="https://raw.githubusercontent.com/cdua-org/ReconSR/main/docker"

sudo curl -fsSL ${REPO}/docker-compose.yaml -o /home/reconsr/docker-compose.yaml
sudo curl -fsSL ${REPO}/.env.example -o /home/reconsr/.env
sudo chmod 0600 /home/reconsr/{docker-compose.yaml,.env}
sudo chown root:root /home/reconsr/{docker-compose.yaml,.env}
```

Configure host IDs:

```bash
sed -i "s/^APP_UID=.*/APP_UID=${APP_UID}/" /home/reconsr/.env
sed -i "s/^APP_GID=.*/APP_GID=${APP_UID}/" /home/reconsr/.env
```

Initialize directories with initial write permissions so default files can be generated:

```bash
mkdir -p /home/reconsr/{configs,storage,data,lang,reports}
sudo chown -R ${APP_UID}:${APP_GID} /home/reconsr/{configs,storage,data,lang,reports}
sudo chmod 0700 /home/reconsr/{configs,storage,data,lang,reports}
```

### 3. Optional: Offline Datasets

For instructions on obtaining and organizing offline datasets into subdirectories within `data/`, refer to the [Wiki](https://github.com/cdua-org/ReconSR/wiki/Offline-Datasets).

After adding datasets to `/home/reconsr/data/`, configure ownership and recursive permissions (directories `0700`, files `0400`):

```bash
sudo chown -R ${APP_UID}:${APP_GID} /home/reconsr/data
sudo find /home/reconsr/data -type d -exec chmod 0700 {} +
sudo find /home/reconsr/data -type f -exec chmod 0400 {} +
```

### 4. Pull the Container

```bash
docker compose -f /home/reconsr/docker-compose.yaml --profile tools pull
```

### 5. First-Run Initialization

Run the utility with `--help` once. This bootstraps the environment and automatically generates all default configuration files (`configs/config.txt`, `configs/keys.txt`, `configs/network.txt`, `configs/scope/`, and `lang/en.txt`) on the host disk:

```bash
docker compose -f /home/reconsr/docker-compose.yaml --profile tools run --rm reconsr --help
```

### 6. Post-Initialization Hardening

Apply strict host ownership and permissions, and enforce immutable read-only container mounts in `docker-compose.yaml`:

```bash
if [ -f /home/reconsr/configs/keys.txt ]; then
    sudo chown root:reconsr /home/reconsr/configs
    sudo chmod 0750 /home/reconsr/configs

    sudo chown root:reconsr /home/reconsr/configs/keys.txt
    sudo chmod 0640 /home/reconsr/configs/keys.txt

    sudo sed -i 's/# - \.\/configs\/keys\.txt/- \.\/configs\/keys\.txt/' /home/reconsr/docker-compose.yaml
    sudo sed -i 's/# - \.\/configs\/network\.txt/- \.\/configs\/network\.txt/' /home/reconsr/docker-compose.yaml
else
    echo "Error: Initialization files not found. Complete Step 5 first." >&2
fi
```

#### API Credentials via Docker Secrets (Recommended)

Using **Docker Secrets** is strongly recommended to protect API keys. Storing keys in dedicated secret files prevents credentials from being recorded in shell history, exposed in host process tables or `.env` files, leaked via `docker inspect` (which exposes environment variables in plain text), or modified by the container process.

For instructions on obtaining API keys for each supported service, refer to the [Wiki: API Keys](https://github.com/cdua-org/ReconSR/wiki/API-Keys).

Create the host directory for secrets with restricted access:

```bash
sudo mkdir -p /home/reconsr/secrets
sudo chown root:reconsr /home/reconsr/secrets
sudo chmod 0750 /home/reconsr/secrets
```

For each API key you wish to configure, run its respective command block. This creates the secret file with read-only permissions (`0440 root:reconsr`), opens `nano` to paste your key without exposing it to shell history, and activates the secret definition in `docker-compose.yaml`:

##### AbuseIPDB
```bash
sudo touch /home/reconsr/secrets/abuseipdb.txt
sudo chown root:reconsr /home/reconsr/secrets/abuseipdb.txt
sudo chmod 0440 /home/reconsr/secrets/abuseipdb.txt
sudo nano /home/reconsr/secrets/abuseipdb.txt
sudo sed -i \
    -e 's/^    # secrets:/    secrets:/' \
    -e 's/^# secrets:/secrets:/' \
    -e 's/#   - reconsr_abuseipdb/  - reconsr_abuseipdb/' \
    -e 's/#   reconsr_abuseipdb:/  reconsr_abuseipdb:/' \
    -e 's/#     file: \.\/secrets\/abuseipdb\.txt/    file: \.\/secrets\/abuseipdb\.txt/' \
    /home/reconsr/docker-compose.yaml
```

##### HackerTarget
```bash
sudo touch /home/reconsr/secrets/hackertarget.txt
sudo chown root:reconsr /home/reconsr/secrets/hackertarget.txt
sudo chmod 0440 /home/reconsr/secrets/hackertarget.txt
sudo nano /home/reconsr/secrets/hackertarget.txt
sudo sed -i \
    -e 's/^    # secrets:/    secrets:/' \
    -e 's/^# secrets:/secrets:/' \
    -e 's/#   - reconsr_hackertarget/  - reconsr_hackertarget/' \
    -e 's/#   reconsr_hackertarget:/  reconsr_hackertarget:/' \
    -e 's/#     file: \.\/secrets\/hackertarget\.txt/    file: \.\/secrets\/hackertarget\.txt/' \
    /home/reconsr/docker-compose.yaml
```

##### Shodan
```bash
sudo touch /home/reconsr/secrets/shodan.txt
sudo chown root:reconsr /home/reconsr/secrets/shodan.txt
sudo chmod 0440 /home/reconsr/secrets/shodan.txt
sudo nano /home/reconsr/secrets/shodan.txt
sudo sed -i \
    -e 's/^    # secrets:/    secrets:/' \
    -e 's/^# secrets:/secrets:/' \
    -e 's/#   - reconsr_shodan/  - reconsr_shodan/' \
    -e 's/#   reconsr_shodan:/  reconsr_shodan:/' \
    -e 's/#     file: \.\/secrets\/shodan\.txt/    file: \.\/secrets\/shodan\.txt/' \
    /home/reconsr/docker-compose.yaml
```

##### VirusTotal
```bash
sudo touch /home/reconsr/secrets/virustotal.txt
sudo chown root:reconsr /home/reconsr/secrets/virustotal.txt
sudo chmod 0440 /home/reconsr/secrets/virustotal.txt
sudo nano /home/reconsr/secrets/virustotal.txt
sudo sed -i \
    -e 's/^    # secrets:/    secrets:/' \
    -e 's/^# secrets:/secrets:/' \
    -e 's/#   - reconsr_virustotal/  - reconsr_virustotal/' \
    -e 's/#   reconsr_virustotal:/  reconsr_virustotal:/' \
    -e 's/#     file: \.\/secrets\/virustotal\.txt/    file: \.\/secrets\/virustotal\.txt/' \
    /home/reconsr/docker-compose.yaml
```

##### Hunterio
```bash
sudo touch /home/reconsr/secrets/hunterio.txt
sudo chown root:reconsr /home/reconsr/secrets/hunterio.txt
sudo chmod 0440 /home/reconsr/secrets/hunterio.txt
sudo nano /home/reconsr/secrets/hunterio.txt
sudo sed -i \
    -e 's/^    # secrets:/    secrets:/' \
    -e 's/^# secrets:/secrets:/' \
    -e 's/#   - reconsr_hunterio/  - reconsr_hunterio/' \
    -e 's/#   reconsr_hunterio:/  reconsr_hunterio:/' \
    -e 's/#     file: \.\/secrets\/hunterio\.txt/    file: \.\/secrets\/hunterio\.txt/' \
    /home/reconsr/docker-compose.yaml
```

##### HaveIBeenPwned
```bash
sudo touch /home/reconsr/secrets/haveibeenpwned.txt
sudo chown root:reconsr /home/reconsr/secrets/haveibeenpwned.txt
sudo chmod 0440 /home/reconsr/secrets/haveibeenpwned.txt
sudo nano /home/reconsr/secrets/haveibeenpwned.txt
sudo sed -i \
    -e 's/^    # secrets:/    secrets:/' \
    -e 's/^# secrets:/secrets:/' \
    -e 's/#   - reconsr_haveibeenpwned/  - reconsr_haveibeenpwned/' \
    -e 's/#   reconsr_haveibeenpwned:/  reconsr_haveibeenpwned:/' \
    -e 's/#     file: \.\/secrets\/haveibeenpwned\.txt/    file: \.\/secrets\/haveibeenpwned\.txt/' \
    /home/reconsr/docker-compose.yaml
```

##### Circl
```bash
sudo touch /home/reconsr/secrets/circl.txt
sudo chown root:reconsr /home/reconsr/secrets/circl.txt
sudo chmod 0440 /home/reconsr/secrets/circl.txt
sudo nano /home/reconsr/secrets/circl.txt
sudo sed -i \
    -e 's/^    # secrets:/    secrets:/' \
    -e 's/^# secrets:/secrets:/' \
    -e 's/#   - reconsr_circl/  - reconsr_circl/' \
    -e 's/#   reconsr_circl:/  reconsr_circl:/' \
    -e 's/#     file: \.\/secrets\/circl\.txt/    file: \.\/secrets\/circl\.txt/' \
    /home/reconsr/docker-compose.yaml
```

##### IPinfo
```bash
sudo touch /home/reconsr/secrets/ipinfo.txt
sudo chown root:reconsr /home/reconsr/secrets/ipinfo.txt
sudo chmod 0440 /home/reconsr/secrets/ipinfo.txt
sudo nano /home/reconsr/secrets/ipinfo.txt
sudo sed -i \
    -e 's/^    # secrets:/    secrets:/' \
    -e 's/^# secrets:/secrets:/' \
    -e 's/#   - reconsr_ipinfo/  - reconsr_ipinfo/' \
    -e 's/#   reconsr_ipinfo:/  reconsr_ipinfo:/' \
    -e 's/#     file: \.\/secrets\/ipinfo\.txt/    file: \.\/secrets\/ipinfo\.txt/' \
    /home/reconsr/docker-compose.yaml
```

##### LeakIX
```bash
sudo touch /home/reconsr/secrets/leakix.txt
sudo chown root:reconsr /home/reconsr/secrets/leakix.txt
sudo chmod 0440 /home/reconsr/secrets/leakix.txt
sudo nano /home/reconsr/secrets/leakix.txt
sudo sed -i \
    -e 's/^    # secrets:/    secrets:/' \
    -e 's/^# secrets:/secrets:/' \
    -e 's/#   - reconsr_leakix/  - reconsr_leakix/' \
    -e 's/#   reconsr_leakix:/  reconsr_leakix:/' \
    -e 's/#     file: \.\/secrets\/leakix\.txt/    file: \.\/secrets\/leakix\.txt/' \
    /home/reconsr/docker-compose.yaml
```

##### Netlas
```bash
sudo touch /home/reconsr/secrets/netlas.txt
sudo chown root:reconsr /home/reconsr/secrets/netlas.txt
sudo chmod 0440 /home/reconsr/secrets/netlas.txt
sudo nano /home/reconsr/secrets/netlas.txt
sudo sed -i \
    -e 's/^    # secrets:/    secrets:/' \
    -e 's/^# secrets:/secrets:/' \
    -e 's/#   - reconsr_netlas/  - reconsr_netlas/' \
    -e 's/#   reconsr_netlas:/  reconsr_netlas:/' \
    -e 's/#     file: \.\/secrets\/netlas\.txt/    file: \.\/secrets\/netlas\.txt/' \
    /home/reconsr/docker-compose.yaml
```

#### Alternative Configuration Methods

While Docker Secrets are recommended, credentials may also be configured using alternative methods:

- **Environment Variables**: Define keys in `/home/reconsr/.env` via `RECONSR_<SERVICE>=<KEY>` (see [.env.example](.env.example)).
- **Configuration File**: Populate keys directly in `/home/reconsr/configs/keys.txt`:
  ```bash
  sudo nano /home/reconsr/configs/keys.txt
  ```

#### Credential Precedence

ReconSR evaluates API credentials in hierarchical order:

1. **Docker Secrets** (`secrets/`) — Highest priority (recommended)
2. **Environment Variables**: `RECONSR_<SERVICE>` in `/home/reconsr/.env`
3. **Configuration File**: `/home/reconsr/configs/keys.txt` — Lowest priority

### 7. Shell Alias for Interactive Use

For convenience in interactive SSH sessions, you can define a shell function in `~/.bashrc`:

```bash
nano ~/.bashrc
```

```bash
ReconSR() {
    docker compose -f /home/reconsr/docker-compose.yaml --profile tools run --rm reconsr "$@"
}
```

```bash
source ~/.bashrc
```

All subsequent executions now run in the hardened, privilege-separated environment:

```bash
ReconSR example.com
```

<details>
<summary><strong>Permissions &amp; Ownership</strong></summary>

### Host Permissions & Privilege Separation

The stack enforces strict host-level privilege separation so that even in the event of a container compromise, the process cannot modify deployment manifests or host configuration:

* `root:root` (`0600`): `docker-compose.yaml` and `.env` (accessible exclusively to host root).
* `root:reconsr` (`0750`/`0640`/`0440`): `/home/reconsr` base directory (`0750`), `configs/` directory (`0750` when hardened), `configs/keys.txt` (`0640` when hardened; read-only to container, immutable to runtime process), and `secrets/` directory (`0750` dir, `0440` files; Docker Secrets for API keys).
* `reconsr:reconsr` (`0700`/`0600`, `data/` files `0400`): `storage/` (internal database), `data/` (offline read-only datasets), `lang/` (localization files), `reports/` (scan outputs), and `configs/config.txt` (`0600`). Managed with strict DAC.

| Host path | Owner | Mode | Reason |
| --- | --- | --- | --- |
| `/home/reconsr` | `root:reconsr` | `0750` | Allow service traversal without access for other users |
| `docker-compose.yaml`, `.env` | `root:root` | `0600` | Host-only manifests and environment settings |
| `configs/` | `reconsr:reconsr` / `root:reconsr` | `0700` / `0750` | Initial `0700` for file generation; `0750` when hardened against file modification |
| `configs/keys.txt` (hardened) | `root:reconsr` | `0640` | Read-only to service account, writable exclusively by host root |
| `secrets/` | `root:reconsr` | `0750` / `0440` | Docker secret files for API keys, read-only to service |
| `configs/config.txt` | `reconsr:reconsr` | `0600` | Configuration file writable by ReconSR |
| `storage/` | `reconsr:reconsr` | `0700`/`0600` | Private runtime database and cache storage |
| `data/` | `reconsr:reconsr` | `0700`/`0400` | Offline datasets (MaxMind MMDB, IP2Location BIN), read-only |
| `lang/` | `reconsr:reconsr` | `0700`/`0600` | Localization files generated and used by ReconSR |
| `reports/` | `reconsr:reconsr` | `0700`/`0600` | Generated OSINT scan results and HTML graphs |

### One-Shot Permission Reset (Running Stack)

Use this self-contained block to apply or restore canonical ownership and permissions on an existing or migrated installation:

```bash
sudo chown root:reconsr /home/reconsr
sudo chmod 0750 /home/reconsr

sudo chown root:root /home/reconsr/{docker-compose.yaml,.env}
sudo chmod 0600 /home/reconsr/{docker-compose.yaml,.env}

sudo chown -R reconsr:reconsr /home/reconsr/{configs,storage,data,lang,reports}
sudo find /home/reconsr/{configs,storage,data,lang,reports} -type d -exec chmod 0700 {} +
sudo find /home/reconsr/{configs,storage,lang,reports} -type f -exec chmod 0600 {} +
sudo find /home/reconsr/data -type f -exec chmod 0400 {} +

if [ -f /home/reconsr/configs/keys.txt ]; then
    sudo chown root:reconsr /home/reconsr/configs
    sudo chmod 0750 /home/reconsr/configs
    sudo chown root:reconsr /home/reconsr/configs/keys.txt
    sudo chmod 0640 /home/reconsr/configs/keys.txt
fi

if [ -d /home/reconsr/secrets ]; then
    sudo chown root:reconsr /home/reconsr/secrets
    sudo chmod 0750 /home/reconsr/secrets
    sudo find /home/reconsr/secrets -type f -exec chown root:reconsr {} +
    sudo find /home/reconsr/secrets -type f -exec chmod 0440 {} +
fi
```

</details>
