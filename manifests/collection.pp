# @summary Installs a CrowdSec collection using `cscli`.
#
# @param cscli_path Path to the cscli binary (defaults to crowdsec::cscli_path from Hiera).
define crowdsec::collection (
  String $cscli_path = '/usr/bin/cscli',
) {
  exec { "crowdsec-collection-${title}":
    command => "${cscli_path} collections install ${title} --error",
    unless  => "${cscli_path} collections inspect ${title} -o raw 2>/dev/null | /bin/grep -qE '^installed: true$'",
    require => [Package['crowdsec'], Exec['crowdsec-hub-update-init']],
  }
}
