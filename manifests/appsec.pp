# @summary Manages CrowdSec AppSec acquisition configuration.
#
# Acts as a collector for AppSec hub items: declares
# `crowdsec::appsec::config` and `crowdsec::appsec::rule` resources for
# the supplied lists and orders them before the appsec.yaml acquisition
# file. The service must see referenced items in the hub before it
# starts, otherwise it fails with "unknown data source appsec".
#
# @param listen_addr Address and port used by the AppSec listener.
# @param appsec_configs List of AppSec config names (`appsec-configs` hub items) to install.
# @param appsec_rules List of AppSec rule names (`appsec-rules` hub items) to install.
class crowdsec::appsec (
  String        $listen_addr    = '127.0.0.1:7422',
  Array[String] $appsec_configs = ['crowdsecurity/appsec-default'],
  Array[String] $appsec_rules   = [],
) {
  crowdsec::appsec::config { $appsec_configs:
    before => File['/etc/crowdsec/acquis.d/appsec.yaml'],
    notify => Service['crowdsec'],
  }

  crowdsec::appsec::rule { $appsec_rules:
    before => File['/etc/crowdsec/acquis.d/appsec.yaml'],
    notify => Service['crowdsec'],
  }

  file { '/etc/crowdsec/acquis.d/appsec.yaml':
    ensure  => file,
    owner   => 'root',
    group   => 'root',
    mode    => '0644',
    content => epp('crowdsec/appsec.yaml.epp', {
      'listen_addr'    => $listen_addr,
      'appsec_configs' => $appsec_configs,
    }),
    notify  => Service['crowdsec'],
    require => File['/etc/crowdsec/acquis.d'],
  }
}
