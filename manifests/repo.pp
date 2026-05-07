# @summary Configures the CrowdSec upstream package repository.
#
# Supports Debian/Ubuntu (APT) and RedHat/CentOS/Rocky/AlmaLinux (YUM/DNF).
# All repository parameters are provided via module Hiera data
# (data/Debian.yaml, data/RedHat.yaml) so adding a new distribution only
# requires a new data file — no manifest changes needed.
#
# @param apt_location    APT repository URL.
# @param apt_release     APT release (e.g. 'any' for packagecloud.io).
# @param apt_repos       APT component (e.g. 'main').
# @param apt_key_name    Filename for the APT signing key in /etc/apt/keyrings/.
# @param apt_key_source  URL to download the APT signing key from.
# @param apt_legacy_sources
#   List of stale .list files to remove before apt-get update runs.
#   Used to eliminate conflicts from the packagecloud.io bootstrap script.
# @param yum_baseurl   YUM/DNF repository base URL. The string $basearch is
#   a YUM macro expanded at runtime, not a Puppet variable.
# @param yum_gpgkey    URL to the GPG key used for RPM signature verification.
# @param yum_gpgcheck  Whether to verify RPM signatures (default: true).
class crowdsec::repo (
  # Debian / Ubuntu — APT
  Optional[String] $apt_location      = undef,
  Optional[String] $apt_release       = undef,
  Optional[String] $apt_repos         = undef,
  Optional[String] $apt_key_name      = undef,
  Optional[String] $apt_key_source    = undef,
  Array[String]    $apt_legacy_sources = [],
  # RedHat / CentOS / Rocky / AlmaLinux — YUM/DNF
  Optional[String] $yum_baseurl  = undef,
  Optional[String] $yum_gpgkey   = undef,
  Boolean          $yum_gpgcheck = true,
) {
  case $facts['os']['family'] {
    'Debian': {
      include apt

      $apt_legacy_sources.each |String $source| {
        file { $source:
          ensure => absent,
          before => Class['apt::update'],
        }
      }

      apt::source { 'crowdsec':
        location => $apt_location,
        release  => $apt_release,
        repos    => $apt_repos,
        key      => {
          'name'   => $apt_key_name,
          'source' => $apt_key_source,
        },
      }
    }

    'RedHat': {
      $gpgcheck_int = $yum_gpgcheck ? { true => 1, false => 0 }
      yumrepo { 'crowdsec':
        ensure   => present,
        descr    => 'CrowdSec',
        baseurl  => $yum_baseurl,
        gpgkey   => $yum_gpgkey,
        gpgcheck => $gpgcheck_int,
        enabled  => 1,
      }
    }

    default: {
      fail("crowdsec::repo: OS family '${facts['os']['family']}' is not supported")
    }
  }
}
