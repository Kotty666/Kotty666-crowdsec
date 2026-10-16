# @summary Installs and configures the CrowdSec firewall bouncer (nftables or iptables).
#
# The package-provided `/etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml`
# is left untouched; all managed settings are written to the `.yaml.local`
# override file, which the bouncer merges on start. This keeps package
# upgrades conflict-free.
#
# The bouncer can run on a host without a local CrowdSec engine. Point
# `api_url` to the (remote) LAPI and supply an API key registered there
# (see `crowdsec::bouncer::api_key`).
#
# @param ensure           Desired package state for the firewall bouncer.
# @param mode             Firewall backend. Selects the package flavour unless `package_name` is set.
# @param package_name     OS package name. Defaults to `crowdsec-firewall-bouncer-<mode>`.
# @param service_name     Systemd service name of the bouncer.
# @param config_path      Path to the local override file.
# @param api_url          URL of the CrowdSec Local API (trailing slash recommended).
# @param api_key          API key registered for this bouncer on the LAPI.
# @param update_frequency Poll interval for decisions in stream mode (Go duration, e.g. `10s`).
# @param deny_action      Action applied to banned IPs.
# @param deny_log         Whether dropped packets of banned IPs are logged (kernel log).
# @param deny_log_prefix  Log prefix used when `deny_log` is enabled.
# @param disable_ipv6     Whether IPv6 handling is disabled.
#
# @example Bouncer against a remote LAPI
#   class { 'crowdsec::bouncer::firewall':
#     api_url => 'https://lapi.example.com:8080/',
#     api_key => Sensitive('0123456789abcdef'),
#   }
class crowdsec::bouncer::firewall (
  Enum['installed', 'latest', 'absent'] $ensure           = 'installed',
  Enum['nftables', 'iptables']          $mode             = 'nftables',
  Optional[String[1]]                   $package_name     = undef,
  String[1]                             $service_name     = 'crowdsec-firewall-bouncer',
  Stdlib::Absolutepath                  $config_path      = '/etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml.local',
  Stdlib::HTTPUrl                       $api_url          = 'http://127.0.0.1:8080/',
  Optional[Sensitive[String[1]]]        $api_key          = undef,
  Pattern[/\A[0-9]+(ms|s|m|h)\z/]       $update_frequency = '10s',
  Enum['DROP', 'REJECT']                $deny_action      = 'DROP',
  Boolean                               $deny_log         = true,
  String[1]                             $deny_log_prefix  = 'crowdsec: ',
  Boolean                               $disable_ipv6     = false,
) {
  $_package_name = pick($package_name, "crowdsec-firewall-bouncer-${mode}")

  package { 'crowdsec-firewall-bouncer':
    ensure => $ensure,
    name   => $_package_name,
  }

  if $ensure == 'absent' {
    file { $config_path:
      ensure => absent,
    }

    service { 'crowdsec-firewall-bouncer':
      ensure => stopped,
      enable => false,
      name   => $service_name,
      before => Package['crowdsec-firewall-bouncer'],
    }
  } else {
    ensure_resource('file', '/etc/crowdsec/bouncers', {
      'ensure' => 'directory',
      'owner'  => 'root',
      'group'  => 'root',
      'mode'   => '0750',
    })
    Package['crowdsec-firewall-bouncer'] -> File['/etc/crowdsec/bouncers']

    file { $config_path:
      ensure  => file,
      owner   => 'root',
      group   => 'root',
      mode    => '0600',
      # Sensitive keeps the API key out of diffs and reports.
      content => Sensitive(epp('crowdsec/firewall-bouncer.yaml.local.epp', {
        'mode'             => $mode,
        'api_url'          => $api_url,
        'api_key'          => $api_key,
        'update_frequency' => $update_frequency,
        'deny_action'      => $deny_action,
        'deny_log'         => $deny_log,
        'deny_log_prefix'  => $deny_log_prefix,
        'disable_ipv6'     => $disable_ipv6,
      })),
      require => File['/etc/crowdsec/bouncers'],
      notify  => Service['crowdsec-firewall-bouncer'],
    }

    service { 'crowdsec-firewall-bouncer':
      ensure  => running,
      enable  => true,
      name    => $service_name,
      require => Package['crowdsec-firewall-bouncer'],
    }
  }
}
