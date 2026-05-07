# @summary Installs and configures the CrowdSec OpenResty bouncer package.
#
# This class manages the bouncer component configuration and can optionally
# manage an OpenResty/nginx http-context Lua hook snippet. The hook is opt-in
# so deployments with complex existing Lua can merge the generated directives
# in their own OpenResty profile instead of loading another Lua block.
#
# @param ensure               Desired package state for the OpenResty bouncer package.
# @param package_name         OS package name (provided via Hiera).
# @param manage_config        Whether to manage the OpenResty bouncer config file.
# @param config_path          Path to the OpenResty bouncer component configuration file.
# @param api_url              URL of the CrowdSec Local API.
# @param api_key              Optional API key used by the bouncer.
# @param mode                 Operating mode for the bouncer.
# @param bouncing_on_type     Type of decisions the bouncer acts on.
# @param fallback_remediation Remediation to apply for unknown decisions.
# @param appsec_url           URL of the AppSec listener. Undef disables AppSec forwarding.
# @param appsec_failure_action Action when AppSec is unreachable.
# @param extra_config         Additional OpenResty bouncer KEY=value settings to append.
# @param manage_nginx_snippet Whether to manage the OpenResty http-context Lua hook snippet.
# @param nginx_snippet_path   Path to the OpenResty/nginx http-context Lua hook snippet.
# @param lua_package_path     Lua package path used by the OpenResty bouncer hook.
# @param lua_cache_size       Shared dict size for the OpenResty bouncer cache.
# @param lua_ssl_trusted_certificate CA bundle path used by Lua HTTPS requests.
# @param resolver             Optional resolver directive for captcha/AppSec HTTP calls.
# @param component_version    Component/version string passed to the CrowdSec Lua library.
class crowdsec::bouncer::openresty (
  Enum['installed', 'latest', 'absent'] $ensure               = 'installed',
  String                                $package_name         = 'crowdsec-openresty-bouncer',
  Boolean                               $manage_config        = true,
  String                                $config_path          = '/etc/crowdsec/bouncers/crowdsec-openresty-bouncer.conf',
  String                                $api_url              = 'http://127.0.0.1:8080',
  Optional[String]                      $api_key              = undef,
  Enum['stream', 'live']                $mode                 = 'stream',
  Enum['all', 'ban', 'captcha']         $bouncing_on_type     = 'all',
  Enum['ban', 'captcha']                $fallback_remediation = 'ban',
  Optional[String]                      $appsec_url           = undef,
  Enum['passthrough', 'deny']           $appsec_failure_action = 'passthrough',
  Hash[String, String]                  $extra_config         = {},
  Boolean                               $manage_nginx_snippet = false,
  String                                $nginx_snippet_path   = '/etc/nginx/conf.d/crowdsec_openresty.conf',
  String                                $lua_package_path     = '$prefix/../lualib/plugins/crowdsec/?.lua;;',
  String                                $lua_cache_size       = '50m',
  String                                $lua_ssl_trusted_certificate = '/etc/ssl/certs/ca-certificates.crt',
  Optional[String]                      $resolver             = undef,
  String                                $component_version    = 'crowdsec-openresty-bouncer/puppet',
) {
  package { 'crowdsec-openresty-bouncer':
    ensure => $ensure,
    name   => $package_name,
  }

  if $manage_nginx_snippet {
    if $ensure == 'absent' {
      file { $nginx_snippet_path:
        ensure  => absent,
        require => Package['crowdsec-openresty-bouncer'],
      }
    } else {
      file { $nginx_snippet_path:
        ensure  => file,
        owner   => 'root',
        group   => 'root',
        mode    => '0644',
        content => epp('crowdsec/openresty-crowdsec-lua.conf.epp', {
          'config_path'                 => $config_path,
          'lua_package_path'            => $lua_package_path,
          'lua_cache_size'              => $lua_cache_size,
          'lua_ssl_trusted_certificate' => $lua_ssl_trusted_certificate,
          'resolver'                    => $resolver,
          'component_version'           => $component_version,
        }),
        require => Package['crowdsec-openresty-bouncer'],
      }
    }
  }

  if $manage_config {
    if $ensure == 'absent' {
      file { $config_path:
        ensure  => absent,
        require => Package['crowdsec-openresty-bouncer'],
      }
    } else {
      file { '/etc/crowdsec/bouncers':
        ensure  => directory,
        owner   => 'root',
        group   => 'root',
        mode    => '0750',
        require => Package['crowdsec-openresty-bouncer'],
      }

      file { $config_path:
        ensure  => file,
        owner   => 'root',
        group   => 'root',
        mode    => '0600',
        content => epp('crowdsec/openresty-bouncer.conf.epp', {
          'api_url'               => $api_url,
          'api_key'               => $api_key,
          'mode'                  => $mode,
          'bouncing_on_type'      => $bouncing_on_type,
          'fallback_remediation'  => $fallback_remediation,
          'appsec_url'            => $appsec_url,
          'appsec_failure_action' => $appsec_failure_action,
          'extra_config'          => $extra_config,
        }),
        require => File['/etc/crowdsec/bouncers'],
      }
    }
  }
}
