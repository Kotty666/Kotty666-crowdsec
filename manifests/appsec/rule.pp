# @summary Installs a CrowdSec AppSec rule using `cscli`.
#
# Requires the `crowdsec` package only — cscli works offline. Callers that
# need this installed before the service starts (e.g. when referenced from
# an AppSec config that is loaded at startup) should pass
# `before => File[...]` and `notify => Service['crowdsec']` as
# metaparameters.
#
# @param cscli_path Path to the cscli binary (defaults to crowdsec::cscli_path from Hiera).
define crowdsec::appsec::rule (
  String $cscli_path = '/usr/bin/cscli',
) {
  exec { "crowdsec-appsec-rule-${title}":
    command => "${cscli_path} appsec-rules install ${title} --error",
    unless  => "${cscli_path} appsec-rules inspect ${title} -o raw 2>/dev/null | /bin/grep -qE '^installed: true$'",
    require => [Package['crowdsec'], Exec['crowdsec-hub-update-init']],
  }
}
