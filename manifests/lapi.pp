# @summary Manages CrowdSec Local API client configuration.
#
# Two modes:
#
# * **Remote LAPI** — both `login` and `password` are supplied (e.g. pinned
#   from Hiera/Vault). The credentials file is rendered from the template
#   so the local watcher authenticates against an external LAPI.
#
# * **Local LAPI** (default) — `login`/`password` are unset. The credentials
#   file is left untouched so the auto-generated values from the crowdsec
#   package postinst keep working. To recover from a previous run that
#   wiped the file (or a database that was reset out of band), Puppet
#   re-registers the local watcher whenever the login in the credentials
#   file is missing from `cscli machines list`.
#
# @param url URL used by local clients to reach the CrowdSec Local API.
# @param login Optional login/machine name for LAPI authentication.
# @param password Optional password for LAPI authentication.
# @param manage_server_listen_uri Whether to manage api.server.listen_uri in /etc/crowdsec/config.yaml.
# @param server_listen_uri Address and port where the local API listens for machines and bouncers.
# @param manage_config_local Whether to manage /etc/crowdsec/config.yaml.local (LAPI server settings overriding the package config).
# @param server_enabled Whether the local API server runs. Set to false for agent-only nodes that report to a remote LAPI (requires manage_config_local).
# @param server_tls_cert_file Optional TLS certificate (full chain) for the local API server (requires manage_config_local).
# @param server_tls_key_file Optional TLS private key for the local API server (requires manage_config_local).
# @param cscli_path Path to the cscli binary (provided via Hiera).
#
# @example Agent-only node reporting to a central LAPI
#   class { 'crowdsec::lapi':
#     url                 => 'https://lapi.example.com:8080/',
#     login               => $trusted['certname'],
#     password            => 'secret',
#     manage_config_local => true,
#     server_enabled      => false,
#   }
#
# @example Central LAPI listening with TLS on all interfaces
#   class { 'crowdsec::lapi':
#     manage_config_local  => true,
#     server_listen_uri    => '[::]:8080',
#     server_tls_cert_file => '/etc/letsencrypt/live/lapi.example.com/fullchain.pem',
#     server_tls_key_file  => '/etc/letsencrypt/live/lapi.example.com/privkey.pem',
#   }
class crowdsec::lapi (
  String           $url                      = 'http://127.0.0.1:8080',
  Optional[String] $login                    = undef,
  Optional[String] $password                 = undef,
  Boolean          $manage_server_listen_uri = false,
  String           $server_listen_uri        = '127.0.0.1:8080',
  Boolean          $manage_config_local      = false,
  Boolean          $server_enabled           = true,
  Optional[Stdlib::Absolutepath] $server_tls_cert_file = undef,
  Optional[Stdlib::Absolutepath] $server_tls_key_file  = undef,
  String           $cscli_path               = '/usr/bin/cscli',
) {
  if ($server_tls_cert_file =~ Undef) != ($server_tls_key_file =~ Undef) {
    fail('crowdsec::lapi: server_tls_cert_file and server_tls_key_file must be set together')
  }

  if $manage_config_local {
    file { '/etc/crowdsec/config.yaml.local':
      ensure  => file,
      owner   => 'root',
      group   => 'root',
      mode    => '0644',
      content => epp('crowdsec/config.yaml.local.epp', {
        'server_enabled'       => $server_enabled,
        'server_listen_uri'    => $server_listen_uri,
        'server_tls_cert_file' => $server_tls_cert_file,
        'server_tls_key_file'  => $server_tls_key_file,
      }),
      require => Package['crowdsec'],
      notify  => Service['crowdsec'],
    }
  }

  if $manage_server_listen_uri {
    file_line { 'crowdsec-lapi-listen-uri':
      ensure  => present,
      path    => '/etc/crowdsec/config.yaml',
      line    => "    listen_uri: ${server_listen_uri}",
      match   => '^\s*listen_uri:\s+.*$',
      require => Package['crowdsec'],
      notify  => Service['crowdsec'],
    }
  }

  if $login and $password {
    file { '/etc/crowdsec/local_api_credentials.yaml':
      ensure  => file,
      owner   => 'root',
      group   => 'root',
      mode    => '0600',
      # Sensitive keeps the password out of diffs and reports.
      content => Sensitive(epp('crowdsec/local_api_credentials.yaml.epp', {
        'url'      => $url,
        'login'    => $login,
        'password' => $password,
      })),
      notify  => Service['crowdsec'],
    }
  } else {
    file { '/usr/local/sbin/crowdsec-ensure-local-watcher-registered':
      ensure  => file,
      owner   => 'root',
      group   => 'root',
      mode    => '0755',
      content => epp('crowdsec/ensure-local-watcher-registered.sh.epp', {
        'cscli_path' => $cscli_path,
      }),
      require => Package['crowdsec'],
    }

    exec { 'crowdsec-register-local-watcher':
      command => "${cscli_path} machines add --auto --force --file /etc/crowdsec/local_api_credentials.yaml",
      unless  => '/usr/local/sbin/crowdsec-ensure-local-watcher-registered',
      require => [
        Package['crowdsec'],
        File['/usr/local/sbin/crowdsec-ensure-local-watcher-registered'],
      ],
      notify  => Service['crowdsec'],
    }
  }
}
