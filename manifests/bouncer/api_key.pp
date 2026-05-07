# @summary Registers a CrowdSec bouncer API key on the local LAPI.
#
# The API key should usually come from Hiera or an encrypted Hiera backend so
# remote remediation components can be provisioned without manual `cscli`
# commands on the LAPI server.
#
# @param api_key API key to register for this bouncer name.
# @param bouncer_name Bouncer name registered in CrowdSec; defaults to the resource title.
# @param cscli_path Path to the cscli binary (provided via Hiera).
define crowdsec::bouncer::api_key (
  String $api_key,
  Pattern[/\A[A-Za-z0-9_.-]+\z/] $bouncer_name = $title,
  String $cscli_path = '/usr/bin/cscli',
) {
  exec { "crowdsec-bouncer-add-${bouncer_name}":
    command => "${cscli_path} bouncers add ${bouncer_name} --key ${api_key}",
    unless  => "${cscli_path} bouncers inspect ${bouncer_name} >/dev/null 2>&1",
    require => Service['crowdsec'],
  }
}
