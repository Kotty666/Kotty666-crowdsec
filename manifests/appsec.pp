# @summary Manages CrowdSec AppSec acquisition configuration.
#
# Acts as a collector for AppSec hub items: declares
# `crowdsec::appsec::config` and `crowdsec::appsec::rule` resources for
# the supplied lists and orders them before the appsec.yaml acquisition
# file. The service must see referenced items in the hub before it
# starts, otherwise it fails with "unknown data source appsec".
#
# @param listen_addr Address and port used by the AppSec listener.
# @param auth_timeout Timeout for validating bouncer API keys against the LAPI (Go duration, e.g. `1s`). Raise it when the LAPI is remote; undef keeps the CrowdSec default (200ms).
# @param appsec_configs List of AppSec config names (`appsec-configs` hub items) to install.
# @param appsec_rules List of AppSec rule names (`appsec-rules` hub items) to install.
# @param local_appsec_configs Local AppSec configs keyed by config name; each value holds `crowdsec::appsec::local_config` parameters. Present entries are appended to `appsec_configs` in acquis.d/appsec.yaml (after the hub configs, so they can override them).
class crowdsec::appsec (
  String                $listen_addr          = '127.0.0.1:7422',
  Optional[Pattern[/\A[0-9]+(ms|s|m)\z/]] $auth_timeout = undef,
  Array[String]         $appsec_configs       = ['crowdsecurity/appsec-default'],
  Array[String]         $appsec_rules         = [],
  Hash[String[1], Hash] $local_appsec_configs = {},
) {
  crowdsec::appsec::config { $appsec_configs:
    before => File['/etc/crowdsec/acquis.d/appsec.yaml'],
    notify => Service['crowdsec'],
  }

  crowdsec::appsec::rule { $appsec_rules:
    before => File['/etc/crowdsec/acquis.d/appsec.yaml'],
    notify => Service['crowdsec'],
  }

  $local_appsec_configs.each |$config_name, $config_params| {
    crowdsec::appsec::local_config { $config_name:
      *      => $config_params,
      before => File['/etc/crowdsec/acquis.d/appsec.yaml'],
      notify => Service['crowdsec'],
    }
  }

  $active_local_configs = $local_appsec_configs.filter |$config_name, $config_params| {
    $config_params.get('ensure', 'present') != 'absent'
  }.keys

  file { '/etc/crowdsec/acquis.d/appsec.yaml':
    ensure  => file,
    owner   => 'root',
    group   => 'root',
    mode    => '0644',
    content => epp('crowdsec/appsec.yaml.epp', {
      'listen_addr'    => $listen_addr,
      'auth_timeout'   => $auth_timeout,
      'appsec_configs' => $appsec_configs + $active_local_configs,
    }),
    notify  => Service['crowdsec'],
    require => File['/etc/crowdsec/acquis.d'],
  }
}
