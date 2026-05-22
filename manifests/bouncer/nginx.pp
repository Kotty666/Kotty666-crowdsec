# @summary Installs and configures the CrowdSec NGINX bouncer.
#
# @param ensure               Desired package state for the NGINX bouncer package.
# @param package_name         OS package name (provided via Hiera).
# @param manage_config        Whether to manage the local bouncer config overrides.
# @param config_path          Path to the package-provided bouncer config read by the Lua hook.
# @param local_config_path    Path to the local bouncer config override file.
# @param api_url              URL of the CrowdSec Local API.
# @param api_key              Optional API key used by the bouncer.
# @param mode                 Operating mode for the bouncer.
# @param bouncing_on_type     Type of decisions the bouncer acts on.
# @param appsec_url           URL of the AppSec listener. Undef disables AppSec forwarding.
# @param appsec_failure_action Action when AppSec is unreachable.
# @param request_timeout      Timeout (ms) for Lua HTTP calls to the LAPI. Default 5000.
# @param update_frequency     Optional stream-mode poll interval (seconds).
# @param captcha_provider     Optional captcha provider (e.g. recaptcha, hcaptcha, turnstile).
# @param captcha_site_key     Optional captcha site key.
# @param captcha_secret_key   Optional captcha secret key.
# @param ban_template_path    Optional path to a custom HTML template for ban responses.
# @param redirect_location    Optional URL/location to redirect banned clients to.
# @param manage_nginx_snippet Whether to manage the nginx http-context Lua hook snippet.
# @param nginx_snippet_path   Path to the nginx http-context Lua hook snippet.
# @param manage_nginx_conf_include Whether to ensure nginx includes the directory containing the Lua hook.
# @param nginx_conf_path      Path to the main nginx configuration file.
# @param nginx_conf_include   Include glob that loads nginx http-context snippets.
# @param nginx_conf_include_match Regex used to find an existing include line before adding one.
# @param lua_package_path     Lua package path used by the nginx bouncer hook.
# @param lua_cache_size       Shared dict size for the nginx bouncer cache.
# @param lua_ssl_trusted_certificate CA bundle path used by Lua HTTPS requests.
# @param resolver             Optional resolver directive for captcha/AppSec HTTP calls.
# @param component_version    Component/version string passed to the CrowdSec Lua library.
class crowdsec::bouncer::nginx (
  Enum['installed', 'latest', 'absent'] $ensure                      = 'installed',
  String                                $package_name                = 'crowdsec-nginx-bouncer',
  Boolean                               $manage_config               = true,
  String                                $config_path                 = '/etc/crowdsec/bouncers/crowdsec-nginx-bouncer.conf',
  String                                $local_config_path           = '/etc/crowdsec/bouncers/crowdsec-nginx-bouncer.conf.local',
  String                                $api_url                     = 'http://127.0.0.1:8080',
  Optional[String]                      $api_key                     = undef,
  Enum['stream', 'live']                $mode                        = 'stream',
  Enum['all', 'ban', 'captcha']         $bouncing_on_type            = 'ban',
  Optional[String]                      $appsec_url                  = undef,
  Enum['passthrough', 'deny']           $appsec_failure_action        = 'passthrough',
  Integer[1]                            $request_timeout             = 5000,
  Optional[Integer[1]]                  $update_frequency            = undef,
  Optional[Enum['recaptcha', 'hcaptcha', 'turnstile']] $captcha_provider = undef,
  Optional[String]                      $captcha_site_key            = undef,
  Optional[String]                      $captcha_secret_key          = undef,
  Optional[String]                      $ban_template_path           = undef,
  Optional[String]                      $redirect_location           = undef,
  Boolean                               $manage_nginx_snippet        = true,
  String                                $nginx_snippet_path          = '/etc/nginx/conf.d/crowdsec_nginx.conf',
  Boolean                               $manage_nginx_conf_include   = true,
  String                                $nginx_conf_path             = '/etc/nginx/nginx.conf',
  String                                $nginx_conf_include          = '/etc/nginx/conf.d/*.conf',
  String                                $nginx_conf_include_match    = '^\s*include\s+/etc/nginx/conf\.d/\*\.conf;\s*$',
  String                                $lua_package_path            = '/usr/lib/crowdsec/lua/?.lua;;',
  String                                $lua_cache_size              = '50m',
  String                                $lua_ssl_trusted_certificate = '/etc/ssl/certs/ca-certificates.crt',
  Optional[String]                      $resolver                    = undef,
  String                                $component_version           = 'crowdsec-nginx-bouncer/puppet',
) {
  package { 'crowdsec-nginx-bouncer':
    ensure => $ensure,
    name   => $package_name,
  }

  if $manage_nginx_snippet {
    if $ensure == 'absent' {
      file { $nginx_snippet_path:
        ensure  => absent,
        require => Package['crowdsec-nginx-bouncer'],
      }
    } else {
      file { $nginx_snippet_path:
        ensure  => file,
        owner   => 'root',
        group   => 'root',
        mode    => '0644',
        content => epp('crowdsec/nginx-crowdsec-lua.conf.epp', {
          'config_path'                 => $config_path,
          'lua_package_path'            => $lua_package_path,
          'lua_cache_size'              => $lua_cache_size,
          'lua_ssl_trusted_certificate' => $lua_ssl_trusted_certificate,
          'resolver'                    => $resolver,
          'component_version'           => $component_version,
        }),
        require => Package['crowdsec-nginx-bouncer'],
      }

      if $manage_nginx_conf_include {
        file_line { 'crowdsec-nginx-conf-d-include':
          path    => $nginx_conf_path,
          line    => "  include ${nginx_conf_include};",
          match   => $nginx_conf_include_match,
          after   => '^\s*http\s*\{',
          require => File[$nginx_snippet_path],
        }
      }
    }
  }

  if $manage_config {
    if $ensure == 'absent' {
      file { $local_config_path:
        ensure  => absent,
        require => Package['crowdsec-nginx-bouncer'],
      }
    } else {
      ensure_resource('file', '/etc/crowdsec/bouncers', {
        'ensure' => 'directory',
        'owner'  => 'root',
        'group'  => 'root',
        'mode'   => '0750',
      })
      Package['crowdsec-nginx-bouncer'] -> File['/etc/crowdsec/bouncers']

      file { $local_config_path:
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
          'request_timeout'       => $request_timeout,
          'update_frequency'      => $update_frequency,
          'captcha_provider'      => $captcha_provider,
          'captcha_site_key'      => $captcha_site_key,
          'captcha_secret_key'    => $captcha_secret_key,
          'ban_template_path'     => $ban_template_path,
          'redirect_location'     => $redirect_location,
        }),
        require => File['/etc/crowdsec/bouncers'],
      }
    }
  }
}
