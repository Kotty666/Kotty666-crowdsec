# @summary Installs and manages the CrowdSec engine service.
#
# @param ensure       Desired package state for the CrowdSec engine.
# @param package_name OS package name for CrowdSec (provided via Hiera).
# @param service_name OS service name for CrowdSec (provided via Hiera).
# @param cscli_path   Path to the cscli binary (provided via Hiera).
class crowdsec::engine (
  Enum['installed', 'latest', 'absent'] $ensure       = 'installed',
  String                                $package_name = 'crowdsec',
  String                                $service_name = 'crowdsec',
  String                                $cscli_path   = '/usr/bin/cscli',
) {
  # Resource title stays 'crowdsec' so other classes can reference
  # Package['crowdsec'] / Service['crowdsec'] regardless of the actual name.
  package { 'crowdsec':
    ensure => $ensure,
    name   => $package_name,
  }

  # The package creates /etc/crowdsec but not necessarily acquis.d on all
  # versions; manage it explicitly so acquisition and appsec file resources
  # can safely depend on it regardless of apply order.
  file { '/etc/crowdsec/acquis.d':
    ensure  => directory,
    owner   => 'root',
    group   => 'root',
    mode    => '0750',
    require => Package['crowdsec'],
  }

  # Bouncer config directory. Normally created by the crowdsec package, but
  # if /etc/crowdsec was wiped manually (or the package was purged while a
  # bouncer package stayed installed) the directory may be missing when a
  # bouncer config file resource tries to write into it.
  file { '/etc/crowdsec/bouncers':
    ensure  => directory,
    owner   => 'root',
    group   => 'root',
    mode    => '0750',
    require => Package['crowdsec'],
  }

  # Enrichment parser directory used by crowdsec::whitelists. Normally
  # created by the crowdsec package, but managed explicitly so the
  # puppet-managed whitelist parser can be dropped regardless of package
  # version or apply order.
  file { '/etc/crowdsec/parsers/s02-enrich':
    ensure  => directory,
    owner   => 'root',
    group   => 'root',
    mode    => '0755',
    require => Package['crowdsec'],
  }

  # Refresh the local hub index whenever the crowdsec package is
  # installed/upgraded so subsequent `cscli <type> install` calls can find
  # items. Refreshonly avoids running on every Puppet apply.
  exec { 'crowdsec-hub-update-init':
    command     => "${cscli_path} hub update",
    refreshonly => true,
    subscribe   => Package['crowdsec'],
  }

  service { 'crowdsec':
    ensure  => running,
    enable  => true,
    name    => $service_name,
    require => Package['crowdsec'],
  }
}
