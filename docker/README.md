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

Initialize directories and set permissions:

```bash
mkdir -p /home/reconsr/{configs,storage,data,lang,reports}
sudo chown -R ${APP_UID}:${APP_UID} /home/reconsr/{configs,storage,data,lang,reports}
sudo chmod 0700 /home/reconsr/{configs,storage,data,lang,reports}
```

### 3. Optional: Offline Datasets

For instructions on obtaining and organizing offline datasets into subdirectories within `data/`, refer to the [Wiki](https://github.com/cdua-org/ReconSR/wiki/Offline-Datasets).

After adding datasets to `/home/reconsr/data/`, configure ownership and recursive permissions (directories `0700`, files `0600`):

```bash
sudo chown -R ${APP_UID}:${APP_GID} /home/reconsr/data
sudo find /home/reconsr/data -type d -exec chmod 0700 {} +
sudo find /home/reconsr/data -type f -exec chmod 0600 {} +
```

### 4. Pull the Container

```bash
docker compose -f /home/reconsr/docker-compose.yaml --profile tools pull
```

### 5. Shell Alias for Interactive Use

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

Usage:

```bash
ReconSR --help
```
