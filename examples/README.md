# Examples

Beispielkonfigurationen für typische Einsatzszenarien.

## Enthaltene Beispiele

1. `minimal.pp`
   - Minimalinstallation mit Repo + Engine
   - sinnvoll für den schnellen Start

2. `engine_only_external_repo.pp`
   - installiert nur die Engine
   - gedacht für Umgebungen, in denen Paketquellen zentral bereitgestellt werden

3. `reverse_proxy_nginx.pp`
   - klassischer Reverse-Proxy-Host mit Nginx-Logs, Collections und Nginx-Bouncer

4. `appsec_with_nginx_bouncer.pp`
   - Reverse-Proxy plus AppSec/WAF-nahe Konfiguration
   - zusätzliche AppSec-Collections

5. `openresty_bouncer.pp`
   - separates Bouncer-Szenario für OpenResty

5a. `openresty_puppet_nginx_bouncer.pp`
   - OpenResty wird über `puppet-nginx` verwaltet
   - CrowdSec-Lua-Hook liegt als Puppet-managed conf.d-Snippet im Katalog

6. `profile_crowdsec_proxy.pp`
   - Beispiel für ein Wrapper-Profil (`profile::crowdsec_proxy`)
   - bündelt Top-Level-Parameter (`collections`, `whitelists`, `console_enroll_key`)
   - ergänzt Nginx-Acquisition, Nginx-Bouncer und optional AppSec

7. `hiera/nodes/crowdsec-lapi.example.com.yaml`
   - Hiera-Beispiel für einen zentralen CrowdSec LAPI/Engine-Server
   - öffnet `api.server.listen_uri` für entfernte Bouncer
   - registriert Bouncer-API-Keys aus Hiera

8. `hiera/nodes/openresty-proxy-01.example.com.yaml`
   - Hiera-Beispiel für einen entfernten OpenResty-Bouncer
   - verbindet den Bouncer mit der zentralen LAPI-URL und dem passenden Key
   - lässt komplexe OpenResty-/Lua-Konfiguration im OpenResty-Profil

## Nutzung

Beispiele können direkt als Vorlage in Rollen/Profile oder Node-Definitionen übernommen und an lokale Anforderungen (API-Key, Pfade, Modus) angepasst werden.
