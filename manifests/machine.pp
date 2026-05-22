# @summary Registers a CrowdSec machine (log processor / agent) on the local LAPI.
#
# Mirrors `crowdsec::bouncer::api_key` but for machines: remote log-processor
# nodes authenticate to LAPI with a login/password pair rather than an API
# key. Registering the machine here lets remote nodes connect with the same
# credentials managed via Hiera (preferably hiera-eyaml).
#
# Note: the password is only consumed on first registration. Rotating the
# password here will not re-register an existing machine; remove it via
# `cscli machines delete <name>` on LAPI to force re-registration.
#
# @param password Password the remote machine will use to authenticate.
# @param machine_name Machine name registered in CrowdSec; defaults to the resource title.
# @param cscli_path Path to the cscli binary (provided via Hiera).
define crowdsec::machine (
  String $password,
  Pattern[/\A[A-Za-z0-9_.-]+\z/] $machine_name = $title,
  String $cscli_path = '/usr/bin/cscli',
) {
  # Single-quote-wrap the password so shell metacharacters in it cannot
  # break the exec or be interpreted. Embedded single quotes are escaped
  # using the standard '\'' shell idiom.
  $quoted_password = "'${regsubst($password, "'", "'\\\\''", 'G')}'"

  # `-f -` writes the rendered credentials YAML to stdout instead of the
  # default /etc/crowdsec/local_api_credentials.yaml — which on the LAPI
  # host already belongs to the local watcher. We discard the stdout YAML
  # because the remote node configures the same login/password via
  # crowdsec::lapi::login / ::password from Hiera.
  exec { "crowdsec-machine-add-${machine_name}":
    command => "${cscli_path} machines add ${machine_name} --password ${quoted_password} -f - >/dev/null",
    unless  => "${cscli_path} machines list -o raw 2>/dev/null | cut -d, -f1 | grep -Fxq ${machine_name}",
    require => Service['crowdsec'],
    path    => ['/usr/bin', '/bin'],
  }
}
