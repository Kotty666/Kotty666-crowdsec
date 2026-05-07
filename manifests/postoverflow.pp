# @summary Installs a CrowdSec postoverflow using `cscli`.
#
# @param cscli_path Path to the cscli binary (defaults to crowdsec::cscli_path from Hiera).
define crowdsec::postoverflow (
  String $cscli_path = '/usr/bin/cscli',
) {
  exec { "crowdsec-postoverflow-${title}":
    command => "${cscli_path} postoverflows install ${title} --error",
    unless  => "${cscli_path} postoverflows inspect ${title} -o raw 2>/dev/null | /bin/grep -qE '^installed: true$'",
    require => [Package['crowdsec'], Exec['crowdsec-hub-update-init']],
  }
}
