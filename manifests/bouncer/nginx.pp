# @summary Installs and configures the CrowdSec NGINX bouncer.
#
# @param ensure               Desired package state for the NGINX bouncer package.
# @param package_name         OS package name (provided via Hiera).
# @param api_url              URL of the CrowdSec Local API.
# @param api_key              Optional API key used by the bouncer.
# @param mode                 Operating mode for the bouncer.
# @param bouncing_on_type     Type of decisions the bouncer acts on.
# @param appsec_url           URL of the AppSec listener. Empty string disables AppSec forwarding.
# @param appsec_failure_action Action when AppSec is unreachable.
class crowdsec::bouncer::nginx (
  Enum['installed', 'latest', 'absent'] $ensure               = 'installed',
  String                                $package_name         = 'crowdsec-nginx-bouncer',
  String                                $api_url              = 'http://127.0.0.1:8080',
  Optional[String]                      $api_key              = undef,
  Enum['stream', 'live']                $mode                 = 'stream',
  Enum['all', 'ban', 'captcha']         $bouncing_on_type     = 'ban',
  Optional[String]                      $appsec_url           = undef,
  Enum['passthrough', 'deny']           $appsec_failure_action = 'passthrough',
) {
  package { 'crowdsec-nginx-bouncer':
    ensure => $ensure,
    name   => $package_name,
  }

  # /etc/nginx/conf.d/crowdsec_nginx.conf is provided and managed by the
  # crowdsec-nginx-bouncer package; Puppet must not overwrite it.

  file { '/etc/crowdsec/bouncers/crowdsec-nginx-bouncer.conf.local':
    ensure  => file,
    owner   => 'root',
    group   => 'root',
    mode    => '0600',
    content => epp('crowdsec/nginx-bouncer.conf.epp', {
      'api_url'               => $api_url,
      'api_key'               => $api_key,
      'mode'                  => $mode,
      'bouncing_on_type'      => $bouncing_on_type,
      'appsec_url'            => $appsec_url,
      'appsec_failure_action' => $appsec_failure_action,
    }),
    require => Package['crowdsec-nginx-bouncer'],
  }
}
