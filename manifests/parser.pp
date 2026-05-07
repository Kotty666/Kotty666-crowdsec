# @summary Installs a CrowdSec parser using `cscli`.
#
# @param cscli_path Path to the cscli binary (defaults to crowdsec::cscli_path from Hiera).
define crowdsec::parser (
  String $cscli_path = '/usr/bin/cscli',
) {
  exec { "crowdsec-parser-${title}":
    command => "${cscli_path} parsers install ${title} --error",
    unless  => "${cscli_path} parsers inspect ${title} -o raw 2>/dev/null | /bin/grep -qE '^installed: true$'",
    require => [Package['crowdsec'], Exec['crowdsec-hub-update-init']],
  }
}
