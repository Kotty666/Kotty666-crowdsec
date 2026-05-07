# @summary Installs a CrowdSec scenario using `cscli`.
#
# @param cscli_path Path to the cscli binary (defaults to crowdsec::cscli_path from Hiera).
define crowdsec::scenario (
  String $cscli_path = '/usr/bin/cscli',
) {
  exec { "crowdsec-scenario-${title}":
    command => "${cscli_path} scenarios install ${title} --error",
    unless  => "${cscli_path} scenarios inspect ${title} -o raw 2>/dev/null | /bin/grep -qE '^installed: true$'",
    require => [Package['crowdsec'], Exec['crowdsec-hub-update-init']],
  }
}
