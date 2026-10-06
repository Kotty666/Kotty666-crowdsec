# @summary Manages a local (non-hub) CrowdSec AppSec config file.
#
# Renders `/etc/crowdsec/appsec-configs/<filename>` with the given hooks
# and rule lists. The resource title is used as the AppSec config `name`
# and is what `crowdsec::appsec` references in `acquis.d/appsec.yaml`.
#
# @example Raise the body size limit for Nextcloud uploads
#   crowdsec::appsec::local_config { 'local/nextcloud-upload-tuning':
#     on_load => [
#       { 'apply' => ['SetMaxBodySize(20971520)', 'SetBodySizeExceededAction("partial")'] },
#     ],
#   }
#
# @param ensure Whether the config file should be present or absent.
# @param filename File name below /etc/crowdsec/appsec-configs (defaults to the title with '/' replaced by '-').
# @param inband_rules AppSec rule names/globs evaluated in-band (blocking).
# @param outofband_rules AppSec rule names/globs evaluated out-of-band (non-blocking).
# @param default_remediation Remediation applied on in-band matches (e.g. 'ban', 'captcha').
# @param on_load Hooks run when the config is loaded. Each entry has an `apply` list and an optional `filter`.
# @param pre_eval Hooks run before rule evaluation.
# @param post_eval Hooks run after rule evaluation.
# @param on_match Hooks run when a rule matches.
define crowdsec::appsec::local_config (
  Enum['present', 'absent']   $ensure              = 'present',
  String[1]                   $filename            = "${regsubst($title, '/', '-', 'G')}.yaml",
  Array[String[1]]            $inband_rules        = [],
  Array[String[1]]            $outofband_rules     = [],
  Optional[String[1]]         $default_remediation = undef,
  Array[Crowdsec::AppsecHook] $on_load             = [],
  Array[Crowdsec::AppsecHook] $pre_eval            = [],
  Array[Crowdsec::AppsecHook] $post_eval           = [],
  Array[Crowdsec::AppsecHook] $on_match            = [],
) {
  if $ensure == 'present' {
    $file_ensure = 'file'
    $content = epp('crowdsec/appsec-local-config.yaml.epp', {
      'config_name'         => $title,
      'inband_rules'        => $inband_rules,
      'outofband_rules'     => $outofband_rules,
      'default_remediation' => $default_remediation,
      'hooks'               => {
        'on_load'   => $on_load,
        'pre_eval'  => $pre_eval,
        'post_eval' => $post_eval,
        'on_match'  => $on_match,
      },
    })
  } else {
    $file_ensure = 'absent'
    $content = undef
  }

  file { "/etc/crowdsec/appsec-configs/${filename}":
    ensure  => $file_ensure,
    owner   => 'root',
    group   => 'root',
    mode    => '0644',
    content => $content,
    require => File['/etc/crowdsec/appsec-configs'],
  }
}
