# @summary Nginx als direkter PHP-FPM-Webserver (kein Reverse Proxy).
#
# Strukturell an profile::nginx_proxy angelehnt, aber fuer PHP-Applikationen
# die direkt auf dem Node laufen (FastCGI statt proxy_pass).
# Geeignet fuer PHPBB, WordPress, Nextcloud usw.
#
# ERSTER RUN / BOOTSTRAP:
#   Beim ersten Run existieren die LE-Zertifikate noch nicht.
#   Puppet muss ggf. zweimal laufen:
#     1. Run: Nginx + HTTP-Vhost -> certbot holt Zertifikat
#     2. Run: HTTPS-Vhost wird mit Zertifikat aktiviert
#
# BENOETGTE PUPPET-MODULE (Puppetfile):
#   mod 'puppet-nginx', :latest
#   mod 'puppet-letsencrypt', :latest
#
# HIERA-BEISPIEL MIT ALLEN OPTIONEN: siehe examples/hiera/nodes/forum.example.com.yaml
#
# @param vhosts
#   Hash der Vhosts. Schluessel ist der FQDN. Erlaubte Sub-Keys:
#     www_root             (String)  Pflicht - Dokumenten-Root
#     php_fpm_socket       (String)  Pflicht - Pfad zum PHP-FPM Unix-Socket
#     php_version          (String)  Default: '8.2'
#     php_extra_packages   (Array)   Zusaetzliche PHP-Extensions
#     index_files          (Array)   Default: ['index.php', 'index.html']
#     server_aliases       (Array)   Zusaetzliche Hostnamen (z.B. new.forum.example.com).
#                                    Werden in server_name und ins LE-SAN-Zertifikat aufgenommen.
#     letsencrypt          (Boolean) Default: true
#     ssl_cert             (String)  Manuelles Zertifikat (wenn letsencrypt: false)
#     ssl_key              (String)  Manueller Key (wenn letsencrypt: false)
#     client_max_body_size (String)  Default: $client_max_body_size_default
#     deny_patterns        (Array)   Regex-Pfade die per 'deny all' geblockt werden
#     custom_cfg           (Hash)    Beliebige nginx server{} Direktiven
# @param letsencrypt_email E-Mail-Adresse fuer Let's Encrypt Registrierung.
# @param letsencrypt_server Optionaler ACME-Server (z.B. Staging-URL fuer Tests).
# @param ssl_protocols TLS-Protokollversionen fuer alle HTTPS-Vhosts.
# @param ssl_ciphers Cipher-Suite fuer alle HTTPS-Vhosts.
# @param worker_processes Anzahl Nginx Worker-Prozesse.
# @param worker_connections Max. gleichzeitige Verbindungen pro Worker.
# @param client_max_body_size_default Standard-Upload-Limit (pro Vhost ueberschreibbar).
# @param access_log Pfad zum Nginx Access-Log.
# @param error_log Pfad zum Nginx Error-Log.
# @param use_crowdsec_log_format CrowdSec-kompatibles Log-Format mit X-Forwarded-For aktivieren.
# @param manage_security_headers Globale Security-Header (X-Frame-Options usw.) setzen.
# @param acme_webroot Verzeichnis fuer ACME HTTP-01-Challenge (webroot-Methode).
# lint:ignore:autoloader_layout
class profile::www::nginx_phpfpm (
  Hash             $vhosts                       = {},
  Optional[String] $letsencrypt_email            = undef,
  Optional[String] $letsencrypt_server           = undef,
  String           $ssl_protocols                = 'TLSv1.2 TLSv1.3',
  # lint:ignore:140chars
  String           $ssl_ciphers                  = 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384',
  # lint:endignore
  String           $worker_processes             = 'auto',
  Integer          $worker_connections           = 1024,
  String           $client_max_body_size_default = '10m',
  String           $access_log                   = '/var/log/nginx/access.log',
  String           $error_log                    = '/var/log/nginx/error.log',
  Boolean          $use_crowdsec_log_format       = true,
  Boolean          $manage_security_headers       = true,
  String           $acme_webroot                 = '/var/www/letsencrypt',
) {
  # --- Validierung ---
  $any_vhost_needs_le = $vhosts.reduce(false) |$memo, $entry| {
    $memo or pick($entry[1]['letsencrypt'], true)
  }

  if $any_vhost_needs_le and $letsencrypt_email == undef {
    fail('profile::www::nginx_phpfpm: letsencrypt_email required when any vhost uses Let\'s Encrypt')
  }

  # --- Log-Format (CrowdSec-kompatibel) ---
  if $use_crowdsec_log_format {
    # lint:ignore:140chars
    $log_format = { 'crowdsec' => '$remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent" "$http_x_forwarded_for"' }
    # lint:endignore
    $effective_format_log = 'crowdsec'
  } else {
    $log_format           = {}
    $effective_format_log = undef
  }

  # --- Nginx Basisinstallation ---
  class { 'nginx':
    worker_processes     => $worker_processes,
    worker_connections   => $worker_connections,
    client_max_body_size => $client_max_body_size_default,
    server_purge         => true,
    confd_purge          => true,
    names_hash_max_size  => 1024,
    server_tokens        => 'off',
    log_format           => $log_format,
    http_format_log      => $effective_format_log,
  }

  # --- ACME Webroot ---
  file { $acme_webroot:
    ensure => directory,
    owner  => 'www-data',
    group  => 'www-data',
    mode   => '0755',
  }

  # --- Let's Encrypt ---
  if $any_vhost_needs_le {
    $le_config = $letsencrypt_server ? {
      undef   => { 'email' => $letsencrypt_email },
      default => { 'email' => $letsencrypt_email, 'server' => $letsencrypt_server },
    }

    class { 'letsencrypt':
      email             => $letsencrypt_email,
      config            => $le_config,
      renew_cron_ensure => 'present',
      renew_cron_hour   => 3,
      renew_cron_minute => 30,
      configure_epel    => false,
    }
  }

  # --- Security Headers ---
  $security_headers = $manage_security_headers ? {
    true    => {
      'X-Frame-Options'        => 'SAMEORIGIN',
      'X-Content-Type-Options' => 'nosniff',
      'X-XSS-Protection'       => '1; mode=block',
      'Referrer-Policy'        => 'strict-origin-when-cross-origin',
    },
    default => {},
  }

  # --- FastCGI-Parameter (Standard fuer PHP-FPM) ---
  $default_fastcgi_params = {
    'SCRIPT_FILENAME' => '$document_root$fastcgi_script_name',
    'SCRIPT_NAME'     => '$fastcgi_script_name',
    'HTTP_PROXY'      => '""',
  }

  # --- PHP-FPM-Pakete sammeln (dedupliziert ueber alle Vhosts) ---
  $all_php_packages = $vhosts.reduce([]) |$memo, $entry| {
    $cfg       = $entry[1]
    $version   = pick($cfg['php_version'], '8.2')
    $base_pkgs = [
      "php${version}-fpm",
      "php${version}-mysql",
      "php${version}-gd",
      "php${version}-mbstring",
      "php${version}-xml",
      "php${version}-intl",
      "php${version}-curl",
      "php${version}-zip",
    ]
    $extra_pkgs = pick($cfg['php_extra_packages'], [])
    $memo + $base_pkgs + $extra_pkgs
  }.unique

  package { $all_php_packages:
    ensure => installed,
  }

  # PHP-FPM-Services starten (ein Service pro einzigartiger PHP-Version)
  $php_versions = $vhosts.map |$fqdn, $cfg| {
    pick($cfg['php_version'], '8.2')
  }.unique

  $php_versions.each |String $version| {
    service { "php${version}-fpm":
      ensure  => running,
      enable  => true,
      require => Package["php${version}-fpm"],
    }
  }

  # --- Vhosts ---
  $vhosts.each |String $fqdn, Hash $cfg| {
    $www_root        = $cfg['www_root']
    $php_fpm_socket  = $cfg['php_fpm_socket']
    $php_version     = pick($cfg['php_version'], '8.2')
    $index_files     = pick($cfg['index_files'], ['index.php', 'index.html'])
    $server_aliases  = pick($cfg['server_aliases'], [])
    $use_letsencrypt = pick($cfg['letsencrypt'], true)
    $client_max_body = pick($cfg['client_max_body_size'], $client_max_body_size_default)
    $deny_patterns   = pick($cfg['deny_patterns'], [])
    $custom_cfg      = pick($cfg['custom_cfg'], {})

    # Primaerer FQDN + alle Aliase als ein server_name-Set.
    # certbot bekommt die gleiche Liste, dann ist der Alias im SAN-Zertifikat enthalten.
    $all_server_names = [$fqdn] + $server_aliases

    # --- HTTP-Vhost: ACME-Challenge + Redirect ---
    nginx::resource::server { "${fqdn}-http":
      server_name          => $all_server_names,
      listen_port          => 80,
      www_root             => $acme_webroot,
      use_default_location => false,
      access_log           => $access_log,
      error_log            => $error_log,
      format_log           => $effective_format_log,
    }

    nginx::resource::location { "${fqdn}-acme":
      server   => "${fqdn}-http",
      location => '/.well-known/acme-challenge/',
      www_root => $acme_webroot,
    }

    nginx::resource::location { "${fqdn}-http-redirect":
      server              => "${fqdn}-http",
      location            => '/',
      location_cfg_append => {
        'return' => "301 https://\$host\$request_uri",
      },
    }

    # --- Let's Encrypt Zertifikat ---
    if $use_letsencrypt {
      $cert_path   = "/etc/letsencrypt/live/${fqdn}/fullchain.pem"
      $key_path    = "/etc/letsencrypt/live/${fqdn}/privkey.pem"
      $cert_exists = $facts.dig('letsencrypt_directory', $fqdn)

      letsencrypt::certonly { $fqdn:
        domains              => $all_server_names,
        plugin               => 'webroot',
        webroot_paths        => [$acme_webroot],
        manage_cron          => false,
        deploy_hook_commands => ['systemctl reload nginx || true'],
        require              => File[$acme_webroot],
      }
      Class['letsencrypt'] -> Letsencrypt::Certonly[$fqdn]
    } else {
      $cert_path   = $cfg['ssl_cert']
      $key_path    = $cfg['ssl_key']
      $cert_exists = true
    }

    # --- HTTPS-Vhost (erst wenn Zertifikat vorhanden) ---
    if $cert_exists {
      nginx::resource::server { $fqdn:
        server_name          => $all_server_names,
        listen_port          => 443,
        ssl                  => true,
        ssl_cert             => $cert_path,
        ssl_key              => $key_path,
        ssl_protocols        => $ssl_protocols,
        ssl_ciphers          => $ssl_ciphers,
        ssl_stapling         => true,
        ssl_stapling_verify  => true,
        www_root             => $www_root,
        index_files          => $index_files,
        use_default_location => false,
        client_max_body_size => $client_max_body,
        access_log           => $access_log,
        error_log            => $error_log,
        format_log           => $effective_format_log,
        add_header           => $security_headers,
        server_cfg_append    => $custom_cfg,
        require              => Package["php${php_version}-fpm"],
      }

      # Root-Location: try_files fuer sauberes PHP-Routing
      nginx::resource::location { "${fqdn}-root":
        server              => $fqdn,
        ssl                 => true,
        ssl_only            => true,
        location            => '/',
        www_root            => $www_root,
        index_files         => $index_files,
        location_cfg_append => {
          'try_files' => '$uri $uri/ /index.php?$query_string',
        },
      }

      # PHP-Handler via FastCGI
      nginx::resource::location { "${fqdn}-php":
        server              => $fqdn,
        ssl                 => true,
        ssl_only            => true,
        location            => '~ \.php$',
        www_root            => $www_root,
        fastcgi             => "unix:${php_fpm_socket}",
        fastcgi_index       => 'index.php',
        fastcgi_param       => $default_fastcgi_params,
        location_cfg_append => {
          'fastcgi_split_path_info' => '^(.+\.php)(/.+)$',
          'try_files'               => '$fastcgi_script_name =404',
        },
      }

      # Statische Dateien mit Browser-Caching
      nginx::resource::location { "${fqdn}-static":
        server              => $fqdn,
        ssl                 => true,
        ssl_only            => true,
        location            => '~* \.(js|css|png|jpg|jpeg|gif|ico|woff|woff2|ttf|svg|webp)$',
        www_root            => $www_root,
        location_cfg_append => {
          'expires'    => '30d',
          'access_log' => 'off',
        },
      }

      # Optionale Deny-Locations (z.B. fuer PHPBB config.php, cache/ usw.)
      $deny_patterns.each |Integer $idx, String $pattern| {
        nginx::resource::location { "${fqdn}-deny-${idx}":
          server              => $fqdn,
          ssl                 => true,
          ssl_only            => true,
          location            => $pattern,
          location_cfg_append => {
            'deny' => 'all',
          },
        }
      }
    } else {
      notice("profile::www::nginx_phpfpm: Zertifikat fuer '${fqdn}' noch nicht vorhanden. HTTPS-Vhost kommt im naechsten Puppet-Run.")
    }
  }
}
# lint:endignore
