# @summary Installs a CrowdSec AppSec config using `cscli`.
#
# Requires the `crowdsec` package only — cscli works offline. Callers that
# need this installed before the service starts (e.g. when referenced from
# `acquis.d/appsec.yaml`) should pass `before => File[...]` and
# `notify => Service['crowdsec']` as metaparameters.
#
# @param cscli_path Path to the cscli binary (defaults to crowdsec::cscli_path from Hiera).
define crowdsec::appsec::config (
  String $cscli_path = '/usr/bin/cscli',
) {
  exec { "crowdsec-appsec-config-${title}":
    command => "${cscli_path} appsec-configs install ${title} --error",
    unless  => "${cscli_path} appsec-configs inspect ${title} -o raw 2>/dev/null | /bin/grep -qE '^installed: true$'",
    require => [Package['crowdsec'], Exec['crowdsec-hub-update-init']],
  }
}
