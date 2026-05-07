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
# @param cscli_path Path to the cscli binary (provided via Hiera).
class crowdsec::lapi (
  String           $url                      = 'http://127.0.0.1:8080',
  Optional[String] $login                    = undef,
  Optional[String] $password                 = undef,
  Boolean          $manage_server_listen_uri = false,
  String           $server_listen_uri        = '127.0.0.1:8080',
  String           $cscli_path               = '/usr/bin/cscli',
) {
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
      content => epp('crowdsec/local_api_credentials.yaml.epp', {
        'url'      => $url,
        'login'    => $login,
        'password' => $password,
      }),
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
