# puppet-crowdsec

Ein modulares Puppet-Framework zur Installation und Verwaltung von CrowdSec.

## Inhalt

- [Überblick](#überblick)
- [Unterstützung](#unterstützung)
- [Setup](#setup)
- [Nutzung](#nutzung)
  - [`class { 'crowdsec': }`](#class--crowdsec-)
  - [`class { 'crowdsec::repo': }`](#class--crowdsecrepo-)
  - [`class { 'crowdsec::engine': }`](#class--crowdsecengine-)
  - [`class { 'crowdsec::lapi': }`](#class--crowdseclapi-)
  - [`crowdsec::collection {}`](#crowdseccollection-)
  - [`crowdsec::acquisition::file {}`](#crowdsecacquisitionfile-)
  - [`class { 'crowdsec::appsec': }`](#class--crowdsecappsec-)
  - [`class { 'crowdsec::bouncer::nginx': }`](#class--crowdsecbouncernginx-)
  - [`class { 'crowdsec::bouncer::openresty': }`](#class--crowdsecbounceropenresty-)
  - [`class { 'crowdsec::bouncer::firewall': }`](#class--crowdsecbouncerfirewall-)
  - [`crowdsec::allowlist {}`](#crowdsecallowlist-)
  - [Zentrale LAPI mit entfernten Bouncern via Hiera](#zentrale-lapi-mit-entfernten-bouncern-via-hiera)
  - [Agent-only Nodes an einer zentralen TLS-LAPI](#agent-only-nodes-an-einer-zentralen-tls-lapi)
- [Kompositionsbeispiele](#kompositionsbeispiele)
- [Testing & CI](#testing--ci)
- [Referenz](#referenz)

## Überblick

Das Modul ist **bewusst granular** aufgebaut. Du kannst die Bausteine einzeln verwenden oder über die Hauptklasse kombinieren:

- **Repo-Verwaltung** (`crowdsec::repo`)
- **Engine-Installation** (`crowdsec::engine`)
- **LAPI-Konfiguration** (`crowdsec::lapi`)
- **Collections** (`crowdsec::collection`)
- **Acquisition-Dateien** (`crowdsec::acquisition::file`)
- **AppSec** (`crowdsec::appsec`)
- **Bouncer** (`crowdsec::bouncer::nginx`, `crowdsec::bouncer::openresty`)

So bleibt das Modul flexibel für unterschiedliche Einsatzszenarien (Reverse Proxy, AppSec, dedizierte Bouncer Hosts, etc.).

## Unterstützung

Siehe `metadata.json` für unterstützte Betriebssysteme, Puppet-Versionen und Abhängigkeiten.

## Setup

### Modul installieren

```bash
puppet module install <namespace>-crowdsec
```

### Abhängigkeiten

- `puppetlabs/apt`
- `puppetlabs/stdlib`

## Nutzung

### `class { 'crowdsec': }`

Orchestriert die zentralen Unterklassen (Repo, Engine, LAPI).

```puppet
class { 'crowdsec':
  manage_repo   => true,
  manage_engine => true,
  manage_lapi   => true,
  collections   => ['crowdsecurity/nginx', 'crowdsecurity/http-cve'],
  whitelists    => ['10.10.33.0/24', '10.10.34.0/24'],
}
```

### `class { 'crowdsec::repo': }`

Richtet das CrowdSec APT-Repository ein.

```puppet
include crowdsec::repo
```

### `class { 'crowdsec::engine': }`

Installiert und aktiviert den CrowdSec Service.

```puppet
class { 'crowdsec::engine':
  ensure => 'installed',
}
```

### `class { 'crowdsec::lapi': }`

Verwaltet lokale LAPI Credentials/URL-Datei.

```puppet
class { 'crowdsec::lapi':
  url => 'http://127.0.0.1:8080',
}
```

### `crowdsec::collection {}`

Installiert CrowdSec Collections idempotent via `cscli`.

```puppet
crowdsec::collection { 'crowdsecurity/nginx': }
crowdsec::collection { 'crowdsecurity/http-cve': }
```

### `crowdsec::acquisition::file {}`

Erzeugt Acquisition-Dateien unter `/etc/crowdsec/acquis.d/*.yaml`.

```puppet
crowdsec::acquisition::file { 'nginx':
  filenames => [
    '/var/log/nginx/access.log',
    '/var/log/nginx/error.log',
  ],
  type => 'nginx',
}
```

### `class { 'crowdsec::appsec': }`

Aktiviert AppSec Acquisition.

```puppet
class { 'crowdsec::appsec':
  listen_addr => '127.0.0.1:7422',
}
```

Eigene (lokale) AppSec-Configs lassen sich über `local_appsec_configs` verwalten. Puppet schreibt sie nach `/etc/crowdsec/appsec-configs/` und hängt sie in `acquis.d/appsec.yaml` hinter die Hub-Configs an. Hooks (`on_load`, `pre_eval`, `post_eval`, `on_match`) bestehen aus einer `apply`-Liste und optional einem `filter`. Mit `ensure: absent` wird die Datei entfernt und der Eintrag aus der Acquisition genommen.

```yaml
crowdsec::appsec::local_appsec_configs:
  'local/nextcloud-upload-tuning':
    on_load:
      - apply:
          - 'SetMaxBodySize(20971520)'
          - 'SetBodySizeExceededAction("partial")'
```

ergibt `/etc/crowdsec/appsec-configs/local-nextcloud-upload-tuning.yaml` sowie:

```yaml
appsec_configs:
  - crowdsecurity/appsec-default
  - local/nextcloud-upload-tuning
```

Einzeln geht es auch direkt über den Defined Type `crowdsec::appsec::local_config` (dann den Namen selbst in `appsec_configs` eintragen – nicht nötig, wenn über die Klasse deklariert).

Läuft die LAPI auf einem entfernten Host, prüft AppSec die Bouncer-Keys dort. Der CrowdSec-Default von 200 ms ist dafür oft zu knapp; mit `auth_timeout` lässt er sich erhöhen:

```puppet
class { 'crowdsec::appsec':
  listen_addr  => '127.0.0.1:7422',
  auth_timeout => '1s',
}
```

### `class { 'crowdsec::bouncer::nginx': }`

Installiert/konfiguriert den Nginx-Bouncer inkl. lokaler Config-Datei und verwaltet standardmäßig den Lua-Hook unter `/etc/nginx/conf.d/crowdsec_nginx.conf`. Zusätzlich stellt die Klasse sicher, dass `/etc/nginx/nginx.conf` diesen `conf.d`-Pfad im `http`-Kontext inkludiert. Das ist wichtig, wenn `puppet-nginx` `conf.d` purged oder `nginx.conf` keinen `conf.d`-Include enthält: Ohne eingebundenen Lua-Hook sieht man nur CrowdSec-Logformate in Nginx, aber der Bouncer wird nicht im Request-Pfad ausgeführt.

```puppet
class { 'crowdsec::bouncer::nginx':
  ensure               => 'installed',
  api_url              => 'http://127.0.0.1:8080',
  api_key              => 'CHANGEME_LONG_RANDOM_KEY',
  mode                 => 'stream',
  manage_nginx_snippet      => true,
  nginx_snippet_path        => '/etc/nginx/conf.d/crowdsec_nginx.conf',
  manage_nginx_conf_include => true,
  nginx_conf_include        => '/etc/nginx/conf.d/*.conf',
}
```

### `class { 'crowdsec::bouncer::openresty': }`

Installiert und konfiguriert den OpenResty-Bouncer. Die bestehende OpenResty-/Lua-Konfiguration wird bewusst nicht überschrieben; binde den vom Paket gelieferten CrowdSec-Lua-Hook in deinem OpenResty-Profil ein oder merge ihn in deine vorhandenen Lua-Blöcke.

```puppet
class { 'crowdsec::bouncer::openresty':
  ensure               => 'installed',
  api_url              => 'http://crowdsec-lapi.example.com:8080',
  api_key              => 'CHANGEME_LONG_RANDOM_KEY',
  mode                 => 'stream',
  manage_nginx_snippet => true,
  nginx_snippet_path   => '/etc/nginx/conf.d/crowdsec_openresty.conf',
}
```

### `class { 'crowdsec::bouncer::firewall': }`

Installiert den Firewall-Bouncer (`crowdsec-firewall-bouncer-nftables` bzw. `-iptables`) und schreibt alle verwalteten Einstellungen nach `/etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml.local`; die Paket-Config bleibt unangetastet. Der Bouncer funktioniert auch ohne lokale Engine. Mit `deny_log: true` (Default) wird jedes von CrowdSec verworfene Paket mit dem Prefix `crowdsec: ` im Kernel-Log protokolliert. Der Dateiinhalt ist `Sensitive`, der API-Key erscheint nicht in Diffs/Reports.

```puppet
class { 'crowdsec::bouncer::firewall':
  mode    => 'nftables',
  api_url => 'https://lapi.example.com:8080/',
  api_key => Sensitive('REPLACE_WITH_LONG_RANDOM_KEY'),
}
```

Hinweis: Wer die Host-Firewall mit `puppet/nftables` verwaltet, sollte `nftables::noflush_tables: ['ip-crowdsec', 'ip6-crowdsec6']` setzen, damit ein Firewall-Reload die Bouncer-Tabellen nicht leert.

### `crowdsec::allowlist {}`

Pflegt eine zentrale LAPI-Allowlist (`cscli allowlists`, CrowdSec >= 1.6.8). Einträge gelten für alle angebundenen Bouncer und auch für Community-Blocklisten. Nur auf dem LAPI-Host verwenden. Einträge werden nur hinzugefügt; entfernte Einträge bitte mit `cscli allowlists remove <name> <wert>` löschen.

```puppet
crowdsec::allowlist { 'office':
  entries => ['192.0.2.10', '198.51.100.0/27', '2001:db8::/48'],
}
```

### Zentrale LAPI mit entfernten Bouncern via Hiera

Auf dem CrowdSec-Server kann die Local API für andere Systeme erreichbar gemacht und die Bouncer-Keys deklarativ registriert werden. Beschränke TCP/8080 zusätzlich per Firewall auf die Bouncer-Hosts und lege die Keys in Produktion verschlüsselt ab (z. B. `hiera-eyaml`).

```yaml
classes:
  include:
    - crowdsec

crowdsec::lapi::manage_server_listen_uri: true
crowdsec::lapi::server_listen_uri: '0.0.0.0:8080'

crowdsec::bouncer_api_keys:
  openresty-proxy-01: 'REPLACE_WITH_LONG_RANDOM_KEY'
```

Auf einem entfernten OpenResty-Bouncer-Host verweist die Bouncer-Konfiguration auf diese zentrale LAPI und nutzt denselben Key. Deine komplexe OpenResty-/Lua-Konfiguration bleibt in deinem OpenResty-Profil; dieses Modul verwaltet nur Paket und Bouncer-Config:

```yaml
classes:
  include:
    - crowdsec::repo
    - crowdsec::bouncer::openresty

crowdsec::bouncer::openresty::api_url: 'http://crowdsec-lapi.example.com:8080'
crowdsec::bouncer::openresty::api_key: 'REPLACE_WITH_LONG_RANDOM_KEY'
crowdsec::bouncer::openresty::mode: 'stream'

# Wenn OpenResty ueber puppet-nginx verwaltet wird und conf.d gepurged wird,
# muss auch der CrowdSec-Lua-Hook im Puppet-Katalog liegen.
crowdsec::bouncer::openresty::manage_nginx_snippet: true
crowdsec::bouncer::openresty::nginx_snippet_path: '/etc/nginx/conf.d/crowdsec_openresty.conf'

crowdsec::bouncer::openresty::extra_config:
  UPDATE_FREQUENCY: '10'
  SSL_VERIFY: 'true'
```

Vollständige Hiera-Beispiele liegen unter `examples/hiera/nodes/`. Der OpenResty-Bouncer braucht zusätzlich den Lua-Hook im OpenResty-`http`-Kontext. Wenn OpenResty über `puppet-nginx` verwaltet wird, ist der pragmatische Weg: `manage_nginx_snippet: true` setzen und `nginx_snippet_path` auf einen Pfad legen, den dein `nginx.conf` im `http`-Kontext inkludiert (bei `puppet-nginx` typischerweise `/etc/nginx/conf.d/*.conf`). So bleibt die Datei trotz `confd_purge` im Puppet-Katalog. Wenn dein OpenResty bereits eigene `init_by_lua*`/`access_by_lua*`-Blöcke im gleichen Kontext nutzt, darfst du den Snippet nicht zusätzlich laden; merge dann die generierten CrowdSec-Blöcke in dein eigenes OpenResty-Profil oder setze `manage_nginx_snippet: false`.

### Agent-only Nodes an einer zentralen TLS-LAPI

`crowdsec::lapi` kann `/etc/crowdsec/config.yaml.local` verwalten (`manage_config_local: true`). Damit lässt sich der lokale API-Server auf reinen Agent-Nodes abschalten bzw. auf dem zentralen Host mit TLS auf allen Interfaces betreiben. Zusätzlich neutralisiert `crowdsec::manage_default_acquisition: true` die bei der Installation auto-generierte `acquis.yaml`, damit Logs, die per `crowdsec::acquisition::file` in `acquis.d/` deklariert sind, nicht doppelt gezählt werden.

```yaml
# Zentraler LAPI-Host
crowdsec::lapi::manage_config_local: true
crowdsec::lapi::server_listen_uri: '[::]:8080'
crowdsec::lapi::server_tls_cert_file: '/etc/letsencrypt/live/lapi.example.com/fullchain.pem'
crowdsec::lapi::server_tls_key_file: '/etc/letsencrypt/live/lapi.example.com/privkey.pem'

# Agent-Node
crowdsec::lapi::manage_config_local: true
crowdsec::lapi::server_enabled: false
crowdsec::lapi::url: 'https://lapi.example.com:8080/'
crowdsec::lapi::login: 'node1.example.com'
crowdsec::lapi::password: 'REPLACE_WITH_LONG_RANDOM_PASSWORD'
```

Die Machine-Credentials werden auf dem LAPI-Host mit `crowdsec::machine` (bzw. `crowdsec::machine_credentials`) registriert. Die Credentials-Datei ist `Sensitive`.

## Kompositionsbeispiele

### Minimal (Engine + Nginx Collection)

```puppet
include crowdsec::repo
include crowdsec::engine

crowdsec::collection { 'crowdsecurity/nginx': }
```

### Reverse Proxy (Nginx Bouncer + Acquisition)

```puppet
include crowdsec

crowdsec::acquisition::file { 'nginx':
  filenames => ['/var/log/nginx/access.log', '/var/log/nginx/error.log'],
  type      => 'nginx',
}

class { 'crowdsec::bouncer::nginx':
  api_url => 'http://127.0.0.1:8080',
  api_key => 'CHANGEME_LONG_RANDOM_KEY',
}
```

### Mit AppSec

```puppet
include crowdsec
include crowdsec::appsec

crowdsec::collection { 'crowdsecurity/appsec-generic-rules': }
crowdsec::collection { 'crowdsecurity/appsec-virtual-patching': }
```


## Beispiele

Vorkonfigurierte, typische Szenarien findest du unter `examples/` inkl. Kurzbeschreibung.

## Testing & CI

- Unit Tests via `rspec-puppet`
- Lint via `puppet-lint`
- GitHub Actions Workflow unter `.github/workflows/ci.yml`

Lokale Commands:

```bash
bundle install
bundle exec puppet-lint manifests/**/*.pp
bundle exec rake spec
```

## Referenz

Eine strukturierte Parameter-/Ressourcenreferenz findest du in `REFERENCE.md`.

