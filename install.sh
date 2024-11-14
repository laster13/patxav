#!/bin/bash

# Arrêter le script en cas d'erreur
set -e

# Variables
PROJECT_DIR="$HOME/projet-riven"
RIVEN_DIR="$PROJECT_DIR/riven"
RIVEN_FRONTEND_DIR="$PROJECT_DIR/riven-frontend"
IP=$(curl -s ifconfig.me)  # IP de remplacement pour localhost
FILE="/home/$USER/seedbox-compose/ssddb"
CURRENT_USER=$(whoami)
STORAGE_PATH="$HOME/seedbox"
middlewares_file="${STORAGE_PATH}/docker/traefik/rules/middlewares.toml"
middlewares_chains_file="${STORAGE_PATH}/docker/traefik/rules/middlewares-chains.toml"
ssdv2_file="${STORAGE_PATH}/docker/traefik/rules/ssdv2.toml"
streamfusion_file="${STORAGE_PATH}/docker/traefik/rules/streamfusion.toml"


# Demande d'informations à l'utilisateur
read -p "Entrez votre nom de domaine principal (ex: votre-domaine.com) : " domain
read -p "Entrez votre email utilisé pour Cloudflare : " email
read -p "Entrez votre clé API Cloudflare : " cloudflare_api_key

# Fonction pour ajouter l'utilisateur au fichier sudoers sans mot de passe
add_user_to_sudoers() {
    SUDOERS_FILE="/etc/sudoers"
    
    # Vérifie si l'utilisateur a déjà la permission d'utiliser sudo sans mot de passe
    if sudo grep -q "^$CURRENT_USER ALL=(ALL) NOPASSWD:ALL" $SUDOERS_FILE; then
        echo "L'utilisateur $CURRENT_USER est déjà configuré dans sudoers sans mot de passe."
    else
        # Ajoute l'utilisateur au fichier sudoers sans mot de passe
        echo "$CURRENT_USER ALL=(ALL) NOPASSWD:ALL" | sudo tee -a $SUDOERS_FILE
        echo "L'utilisateur $CURRENT_USER a été ajouté au fichier sudoers sans mot de passe."
    fi
}

get_zone_id() {
    # Obtenir le Zone ID via le nom de domaine
    response=$(curl -s -X GET "https://api.cloudflare.com/client/v4/zones?name=$domain" \
        -H "X-Auth-Email: $email" \
        -H "X-Auth-Key: $cloudflare_api_key" \
        -H "Content-Type: application/json")

    # Afficher la réponse brute pour le débogage
    echo "Réponse de l'API pour le zone_id :"
    echo "$response"

    # Extraire le zone_id de la réponse
    zone_id=$(echo $response | jq -r '.result[0].id')

    # Vérification si le zone_id est valide
    if [ -z "$zone_id" ] || [ "$zone_id" == "null" ]; then
        echo "Erreur : Impossible de récupérer le zone_id. Vérifiez que le domaine est correct et que l'API Key a les bons droits."
        exit 1
    fi
}

# Fonction pour ajouter un enregistrement DNS
add_dns_record() {
    local subdomain=$1
    curl -s -X POST "https://api.cloudflare.com/client/v4/zones/$zone_id/dns_records" \
        -H "X-Auth-Email: $email" \
        -H "X-Auth-Key: $cloudflare_api_key" \
        -H "Content-Type: application/json" \
        --data "{
            \"type\": \"A\",
            \"name\": \"$subdomain.$domain\",
            \"content\": \"$IP\",
            \"ttl\": 120,
            \"proxied\": true
        }"
    echo "Enregistrement DNS pour $subdomain.$domain créé."
}

# Préparer les fichiers et répertoires nécessaires
prepare_directories() {
  echo "Création des répertoires nécessaires pour Traefik..."
  mkdir -p "${STORAGE_PATH}/docker/traefik/acme" "${STORAGE_PATH}/docker/traefik/rules" "${STORAGE_PATH}/docker/traefik/logs"
  [ ! -f "${STORAGE_PATH}/docker/traefik/acme/acme.json" ] && touch "${STORAGE_PATH}/docker/traefik/acme/acme.json" && chmod 600 "${STORAGE_PATH}/docker/traefik/acme/acme.json"
  touch "${STORAGE_PATH}/docker/traefik/logs/access.log"
}

# Déployer Traefik via Docker
deploy_traefik() {
  echo "Déploiement de Traefik avec Docker..."
docker network inspect traefik_proxy >/dev/null 2>&1 || docker network create traefik_proxy
docker run -d \
  --name traefik \
  --network traefik_proxy \
  --restart unless-stopped \
  -p 80:80 \
  -p 443:443 \
  -v /var/run/docker.sock:/var/run/docker.sock:ro \
  -v "${STORAGE_PATH}/docker/traefik/acme/acme.json:/acme.json" \
  -v "${STORAGE_PATH}/docker/traefik/rules:/rules" \
  -v "${STORAGE_PATH}/docker/traefik/logs:/logs" \
  -e CF_API_EMAIL=$email \
  -e CF_API_KEY=$cloudflare_api_key \
  --label "traefik.enable=true" \
  --label "traefik.http.middlewares.redirect-to-https.redirectscheme.scheme=https" \
  --label "traefik.http.routers.http-catchall.entrypoints=http" \
  --label "traefik.http.routers.http-catchall.middlewares=redirect-to-https" \
  --label "traefik.http.routers.http-catchall.rule=HostRegexp(\`{host:.+}\`)" \
  --label "traefik.http.routers.traefik-rtr.entrypoints=http,https" \
  --label "traefik.http.routers.traefik-rtr.middlewares=chain-no-auth@file" \
  --label "traefik.http.routers.traefik-rtr.rule=Host(\`traefik.$domain\`)" \
  --label "traefik.http.routers.traefik-rtr.service=api@internal" \
  --label "traefik.http.routers.traefik-rtr.tls=true" \
  --label "traefik.http.routers.traefik-rtr.tls.certresolver=letsencrypt" \
  --label "traefik.http.routers.traefik-rtr.tls.domains[0].main=$domain" \
  --label "traefik.http.routers.traefik-rtr.tls.domains[0].sans=*.$domain" \
  traefik:v3.0 \
  --global.checkNewVersion=true \
  --global.sendAnonymousUsage=true \
  --entrypoints.http.address=:80 \
  --entrypoints.https.address=:443 \
  --entrypoints.web.http.redirections.entrypoint.to=https \
  --entrypoints.web.http.redirections.entrypoint.scheme=https \
  --entrypoints.web.http.redirections.entrypoint.permanent=true \
  --api=true \
  --api.dashboard=true \
  --entrypoints.https.forwardedHeaders.trustedIPs=173.245.48.0/20,103.21.244.0/22,103.22.200.0/22,103.31.4.0/22,141.101.64.0/18,108.162.192.0/18,190.93.240.0/20,188.114.96.0/20,197.234.240.0/22,198.41.128.0/17,162.158.0.0/15,104.16.0.0/12,172.64.0.0/13,131.0.72.0/22 \
  --log=true \
  --log.filePath=/logs \
  --log.level=DEBUG \
  --accessLog=true \
  --accessLog.filePath=/logs/access.log \
  --accessLog.bufferingSize=100 \
  --accessLog.filters.statusCodes=204-299,400-499,500-599 \
  --providers.docker=true \
  --providers.docker.exposedByDefault=false \
  --providers.docker.network=traefik_proxy \
  --entrypoints.https.http.tls.certresolver=letsencrypt \
  --entrypoints.https.http.tls=true \
  --providers.file.directory=/rules \
  --providers.file.watch=true \
  --certificatesResolvers.letsencrypt.acme.email=$email \
  --certificatesResolvers.letsencrypt.acme.storage=/acme.json \
  --certificatesResolvers.letsencrypt.acme.dnsChallenge.provider=cloudflare \
  --certificatesResolvers.letsencrypt.acme.dnsChallenge.resolvers=1.1.1.1:53,1.0.0.1:53 \
  --certificatesResolvers.letsencrypt.acme.dnsChallenge.delayBeforeCheck=90
}


# Vérifier si Docker est déjà installé
if ! command -v docker &> /dev/null
then
    echo "Docker n'est pas installé. Installation en cours..."

    # Télécharger le script d'installation officiel de Docker
    curl -fsSL https://get.docker.com -o get-docker.sh

    # Exécuter le script d'installation
    sudo sh get-docker.sh

    # Supprimer le script après installation
    rm get-docker.sh

    # Activer et démarrer Docker
    sudo systemctl enable docker
    sudo systemctl start docker

    echo "Docker a été installé et démarré avec succès."
else
    echo "Docker est déjà installé."
fi

if [ "$(docker ps -q -f name=traefik)" ]; then
  echo "Traefik est déjà installé et en cours d'exécution."
else
  if [ "$(docker ps -a -q -f name=traefik)" ]; then
    echo "Traefik est installé mais n'est pas en cours d'exécution. Le redémarrer..."
    docker start traefik
  else
    echo "Traefik n'est pas installé. Lancement de l'installation."
    prepare_directories
    deploy_traefik
  fi
fi

# Vérification et création du fichier middlewares.toml (seulement chain-no-auth)
if [ ! -f "$middlewares_file" ]; then
  cat <<EOL > "$middlewares_file"
  [http.middlewares.middlewares-rate-limit]
    [http.middlewares.middlewares-rate-limit.rateLimit]
      average = 100
      burst = 50

  [http.middlewares.middlewares-secure-headers]
    [http.middlewares.middlewares-secure-headers.headers]
      accessControlAllowMethods = ["GET", "OPTIONS", "PUT"]
      accessControlMaxAge = 100
      hostsProxyHeaders = ["X-Forwarded-Host"]
      sslRedirect = true
      stsSeconds = 63072000
      stsIncludeSubdomains = true
      stsPreload = true
      forceSTSHeader = true
      customFrameOptionsValue = "SAMEORIGIN"
      contentTypeNosniff = true 
      browserXssFilter = true 
      referrerPolicy = "same-origin" 
      featurePolicy = "camera 'none'; geolocation 'none'; microphone 'none'; payment 'none'; usb 'none'; vr 'none';"
      [http.middlewares.middlewares-secure-headers.headers.customResponseHeaders]
        X-Robots-Tag = "none,noarchive,nosnippet,notranslate,noimageindex,"
        server = ""
EOL
  echo "Fichier middlewares.toml créé."
else
  echo "Fichier middlewares.toml déjà présent."
fi

# Vérification et création du fichier middlewares-chains.toml (seulement chain-no-auth)
if [ ! -f "$middlewares_chains_file" ]; then
  cat <<EOL > "$middlewares_chains_file"
[http.middlewares]
  [http.middlewares.chain-no-auth]
    [http.middlewares.chain-no-auth.chain]
      middlewares = ["middlewares-rate-limit", "middlewares-secure-headers"]
EOL
  echo "Fichier middlewares-chains.toml créé."
else
  echo "Fichier middlewares-chains.toml déjà présent."
fi

# Vérification et création du fichier ssdv2.toml
if [ ! -f "$ssdv2_file" ]; then
  cat <<EOL > "$ssdv2_file"
[http.routers]
  [http.routers.ssdv2-rtr]
      entryPoints = ["https"]
      rule = "Host(\`ssdv2.$domain\`)"
      service = "ssdv2-svc"
      [http.routers.ssdv2-rtr.tls]
        certresolver = "letsencrypt"

  [http.routers.api-rtr]
      entryPoints = ["https"]
      rule = "Host(\`ssdv2.$domain\`) && PathPrefix(\`/api/v1/scripts\`)"
      service = "api-svc"
      [http.routers.api-rtr.tls]
        certresolver = "letsencrypt"

[http.services]
  [http.services.ssdv2-svc]
    [http.services.ssdv2-svc.loadBalancer]
      passHostHeader = true
      [[http.services.ssdv2-svc.loadBalancer.servers]]
        url = "http://$IP:3000"

  [http.services.api-svc]
    [http.services.api-svc.loadBalancer]
      passHostHeader = true
      [[http.services.api-svc.loadBalancer.servers]]
        url = "http://$IP:8080"
EOL
  echo "Fichier ssdv2.toml créé."
else
  echo "Fichier ssdv2.toml déjà présent."
fi

# Vérification et création du fichier streamfusion.toml
if [ ! -f "$streamfusion_file" ]; then
  cat <<EOL > "$streamfusion_file"
[http.routers]
  [http.routers.streamfusion-rtr]
      entryPoints = ["https"]
      rule = "Host(`streamfusion.${domain}`)"
      service = "streamfusion-svc"
      [http.routers.streamfusion-rtr.tls]
        certresolver = "letsencrypt"

[http.services]
  [http.services.streamfusion-svc]
    [http.services.streamfusion-svc.loadBalancer]
      passHostHeader = true
      [[http.services.streamfusion-svc.loadBalancer.servers]]
        url = "http://streamfusion:8080"EOL
  echo "Fichier streamfusion.toml créé."
else
  echo "Fichier streamfusion.toml déjà présent."
fi


# Vérification et création du fichier middlewares.toml
if [ ! -f "$middlewares_file" ]; then
  cat <<EOL > "$middlewares_file"
  [http.middlewares.middlewares-rate-limit]
    [http.middlewares.middlewares-rate-limit.rateLimit]
      average = 100
      burst = 50

  [http.middlewares.middlewares-secure-headers]
    [http.middlewares.middlewares-secure-headers.headers]
      accessControlAllowMethods = ["GET", "OPTIONS", "PUT"]
      accessControlMaxAge = 100
      hostsProxyHeaders = ["X-Forwarded-Host"]
      sslRedirect = true
      stsSeconds = 63072000
      stsIncludeSubdomains = true
      stsPreload = true
      forceSTSHeader = true
      customFrameOptionsValue = "SAMEORIGIN"
      contentTypeNosniff = true 
      browserXssFilter = true 
      referrerPolicy = "same-origin" 
      featurePolicy = "camera 'none'; geolocation 'none'; microphone 'none'; payment 'none'; usb 'none'; vr 'none';"
      [http.middlewares.middlewares-secure-headers.headers.customResponseHeaders]
        X-Robots-Tag = "none,noarchive,nosnippet,notranslate,noimageindex,"
        server = ""
EOL
  echo "Fichier middlewares.toml créé."
else
  echo "Fichier middlewares.toml déjà présent."
fi

# Ajouter l'utilisateur au fichier sudoers
add_user_to_sudoers

# Obtenir le zone_id pour Cloudflare
get_zone_id

# Ajouter les enregistrements DNS pour Traefik et SSDv2
add_dns_record "traefik"
add_dns_record "ssdv2"
add_dns_record "streamfusion"

# Vérifie si le fichier de seedbox existe
if [ ! -f "$FILE" ]; then
    echo "Le fichier $FILE est absent. Clonage du dépôt..."
    sudo git clone https://github.com/projetssd/ssdv2.git /home/${USER}/seedbox-compose
    sudo chown -R ${USER}: /${HOME}/seedbox-compose
else
    echo "Le fichier $FILE existe déjà."
fi

# Installation de NVM et de la dernière version LTS de Node.js
echo "Installation de NVM et de la dernière version LTS de Node.js..."
if [ -d "$HOME/.nvm" ]; then
    rm -rf "$HOME/.nvm"
fi
curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.5/install.sh | bash

export NVM_DIR="$HOME/.nvm"
[ -s "$NVM_DIR/nvm.sh" ] && \. "$NVM_DIR/nvm.sh"
[ -s "$NVM_DIR/bash_completion" ] && \. "$NVM_DIR/bash_completion"

nvm install --lts
nvm use --lts

# Vérifier que Node.js est bien installé via NVM
node -v
npm -v

# Installation de PNPM avec son script autonome
echo "Installation de PNPM avec son script autonome..."
curl -fsSL https://get.pnpm.io/install.sh | sh -

export PNPM_HOME="$HOME/.local/share/pnpm"
export PATH="$PNPM_HOME:$PATH"

# Vérification de l'installation de PNPM
if ! command -v pnpm &> /dev/null; then
    echo "PNPM n'est pas installé correctement. Veuillez vérifier l'installation."
    exit 1
fi

# Installation de la dernière version LTS de Node.js avec PNPM
pnpm env use --global lts

# Installation de Python 3.11+
echo "Installation de Python 3.11+..."
sudo apt-get update
sudo apt-get install -y software-properties-common
sudo add-apt-repository -y ppa:deadsnakes/ppa
sudo apt-get update
sudo apt-get install -y python3.11 python3.11-venv python3.11-dev

export PATH="$HOME/.local/bin:$PATH"

# Installer pip pour Python 3.11
echo "Installation de pip pour Python 3.11..."
curl -sS https://bootstrap.pypa.io/get-pip.py | python3.11

# Mettre à jour setuptools et wheel
echo "Mise à jour de setuptools et wheel..."
pip3.11 install --upgrade setuptools wheel

# Installation de PM2 sans sudo
echo "Installation de PM2..."
pnpm add -g pm2

# Installation de PostgreSQL
echo "Installation de PostgreSQL..."
sudo apt-get install -y postgresql postgresql-contrib

# Suppression de la base de données si elle existe
echo "Suppression de la base de données '$DB_NAME' si elle existe..."
PGPASSWORD="postgres" psql -U postgres -h localhost -c "DROP DATABASE IF EXISTS riven;"
PGPASSWORD="postgres" psql -U postgres -h localhost -c "CREATE DATABASE riven;"


# Création du dossier projet s'il n'existe pas
echo "Création du dossier de projet..."
mkdir -p "$PROJECT_DIR"

# Suppression des dépôts s'ils existent déjà
if [ -d "$RIVEN_FRONTEND_DIR" ]; then
  echo "Suppression du dépôt riven-frontend existant..."
  rm -rf "$RIVEN_FRONTEND_DIR"
fi

if [ -d "$RIVEN_DIR" ]; then
  echo "Suppression du dépôt riven existant..."
  rm -rf "$RIVEN_DIR"
fi

# Clonage des dépôts
echo "Clonage des dépôts..."
git clone https://github.com/laster13/riven-frontend.git "$RIVEN_FRONTEND_DIR"
git clone https://github.com/laster13/riven.git "$RIVEN_DIR"

# Création du fichier .env dans $RIVEN_FRONTEND_DIR
echo "Création du fichier .env dans $RIVEN_FRONTEND_DIR..."
cat <<EOT > "$RIVEN_FRONTEND_DIR/.env"
DIALECT=postgres
DATABASE_URL=postgres://postgres:postgres@localhost:5432/riven
VITE_BACKEND_URL_HTTP=http://$IP:8080
VITE_BACKEND_URL_HTTPS=https://ssdv2.$domain
EOT

echo "Fichier .env créé avec succès dans $RIVEN_FRONTEND_DIR"

# Initialisation npm dans le projet racine
echo "Initialisation de npm..."
npm init -y

# Modification du fichier package.json dans le répertoire racine du projet pour gérer le lancement des services
echo "Modification du package.json..."
cat <<EOL > package.json
{
  "name": "projet-riven",
  "version": "1.0.0",
  "scripts": {
    "install:all": "npm run install:backend && npm run install:frontend",
    "install:backend": "cd riven && pip install poetry && poetry env use python3.11 && poetry install --without dev",
    "install:frontend": "cd riven-frontend && pnpm install",
    "build:frontend": "cd riven-frontend && pnpm run build"
  },
  "devDependencies": {
    "concurrently": "^7.0.0"
  }
}
EOL

# Installation des dépendances frontend
echo "Installation de concurrently et des dépendances du frontend..."
pnpm install

# Installer Poetry dans le dossier riven et configurer Python 3.11
echo "Installation de Poetry et des dépendances backend..."
cd "$RIVEN_DIR"
pip3.11 install cffi
pip3.11 install poetry  # Utiliser pip3.11 pour installer Poetry
poetry env use python3.11  # Utiliser Python 3.11 avec Poetry

# Installer manuellement le package srt sans PEP 517 (si nécessaire)
echo "Installation du package srt sans PEP 517..."
pip3.11 install --no-use-pep517 srt==3.5.3

# Installer les autres dépendances via Poetry
echo "Installation des autres dépendances backend..."
poetry install --without dev  # Installer les dépendances Python sans les dev dependencies

# Installer les dépendances frontend
cd "$RIVEN_FRONTEND_DIR"
pnpm install  # Installer les dépendances pnpm
pnpm run build  # Construire le projet frontend

# Retour au répertoire parent
cd "$PROJECT_DIR"

# Lancer le backend et le frontend avec PM2
echo "Lancement du backend et du frontend avec PM2..."
pm2 start "poetry run python3.11 src/main.py" --name backend --cwd "$RIVEN_DIR"
pm2 start "ORIGIN=https://ssdv2.$domain VITE_BACKEND_URL_HTTPS=https://ssdv2.$domain node build" --name frontend --cwd "$RIVEN_FRONTEND_DIR"

# Afficher la liste des processus gérés par PM2
pm2 list
