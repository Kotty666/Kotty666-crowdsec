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
# @param enabled              Whether the bouncer is enabled. Renders ENABLED=true|false. The Lua bouncer treats a missing or non-true value as disabled, so leaving this at true is required for the bouncer to act on decisions.
# @param api_url              URL of the CrowdSec Local API.
# @param api_key              Optional API key used by the bouncer.
# @param mode                 Operating mode for the bouncer.
# @param cache_expiration     Cache expiration in seconds (CACHE_EXPIRATION).
# @param request_timeout      Request timeout in milliseconds for LAPI calls (REQUEST_TIMEOUT).
# @param update_frequency     Stream-mode update frequency in seconds (UPDATE_FREQUENCY).
# @param enable_internal      Whether to bounce on internal nginx requests (ENABLE_INTERNAL).
# @param ssl_verify           Whether to verify the LAPI TLS certificate (SSL_VERIFY).
# @param bouncing_on_type     Type of decisions the bouncer acts on.
# @param fallback_remediation Remediation to apply for unknown decisions.
# @param exclude_location     Comma-separated list of nginx locations to exclude from bouncing (EXCLUDE_LOCATION).
# @param ban_template_path    Path to the ban HTML template rendered for banned clients.
# @param redirect_location    Optional location to redirect banned clients to (REDIRECT_LOCATION). Takes priority over ret_code.
# @param ret_code             Optional HTTP status code returned for banned clients (RET_CODE).
# @param captcha_provider     Captcha provider (recaptcha, hcaptcha, turnstile) or empty to disable captcha.
# @param captcha_secret_key   Captcha secret key (SECRET_KEY).
# @param captcha_site_key     Captcha site key (SITE_KEY).
# @param captcha_template_path Path to the captcha HTML template.
# @param captcha_expiration   Captcha cookie expiration in seconds (CAPTCHA_EXPIRATION).
# @param appsec_url           URL of the AppSec listener. Undef disables AppSec forwarding.
# @param appsec_failure_action Action when AppSec is unreachable.
# @param appsec_connect_timeout Optional AppSec connect timeout in milliseconds (APPSEC_CONNECT_TIMEOUT).
# @param appsec_send_timeout    Optional AppSec send timeout in milliseconds (APPSEC_SEND_TIMEOUT).
# @param appsec_process_timeout Optional AppSec process timeout in milliseconds (APPSEC_PROCESS_TIMEOUT).
# @param always_send_to_appsec Whether to always forward requests to AppSec (ALWAYS_SEND_TO_APPSEC).
# @param extra_config         Additional OpenResty bouncer KEY=value settings to append. Use this for keys not exposed as dedicated parameters.
# @param manage_nginx_snippet Whether to manage the OpenResty http-context Lua hook snippet.
# @param nginx_snippet_path   Path to the OpenResty/nginx http-context Lua hook snippet.
# @param lua_package_path     Lua package path used by the OpenResty bouncer hook.
# @param lua_cache_size       Shared dict size for the OpenResty bouncer cache.
# @param lua_ssl_trusted_certificate CA bundle path used by Lua HTTPS requests.
# @param resolver             Optional resolver directive for captcha/AppSec HTTP calls.
# @param component_version    Component/version string passed to the CrowdSec Lua library.
class crowdsec::bouncer::openresty (
  Enum['installed', 'latest', 'absent'] $ensure                 = 'installed',
  String                                $package_name           = 'crowdsec-openresty-bouncer',
  Boolean                               $manage_config          = true,
  String                                $config_path            = '/etc/crowdsec/bouncers/crowdsec-openresty-bouncer.conf',
  Boolean                               $enabled                = true,
  String                                $api_url                = 'http://127.0.0.1:8080',
  Optional[String]                      $api_key                = undef,
  Enum['stream', 'live']                $mode                   = 'stream',
  Integer[0]                            $cache_expiration       = 1,
  Integer[0]                            $request_timeout        = 3000,
  Integer[0]                            $update_frequency       = 10,
  Boolean                               $enable_internal        = false,
  Boolean                               $ssl_verify             = true,
  Enum['all', 'ban', 'captcha']         $bouncing_on_type       = 'all',
  Enum['ban', 'captcha']                $fallback_remediation   = 'ban',
  Optional[String]                      $exclude_location       = undef,
  String                                $ban_template_path      = '/var/lib/crowdsec/lua/templates/ban.html',
  Optional[String]                      $redirect_location      = undef,
  Optional[Integer[100, 599]]           $ret_code               = undef,
  Optional[String]                      $captcha_provider       = undef,
  Optional[String]                      $captcha_secret_key     = undef,
  Optional[String]                      $captcha_site_key       = undef,
  String                                $captcha_template_path  = '/var/lib/crowdsec/lua/templates/captcha.html',
  Integer[0]                            $captcha_expiration     = 3600,
  Optional[String]                      $appsec_url             = undef,
  Enum['passthrough', 'deny']           $appsec_failure_action  = 'passthrough',
  Optional[Integer[0]]                  $appsec_connect_timeout = undef,
  Optional[Integer[0]]                  $appsec_send_timeout    = undef,
  Optional[Integer[0]]                  $appsec_process_timeout = undef,
  Boolean                               $always_send_to_appsec  = false,
  Hash[String, String]                  $extra_config           = {},
  Boolean                               $manage_nginx_snippet   = false,
  String                                $nginx_snippet_path     = '/etc/nginx/conf.d/crowdsec_openresty.conf',
  String                                $lua_package_path       = '$prefix/../lualib/plugins/crowdsec/?.lua;;',
  String                                $lua_cache_size         = '50m',
  String                                $lua_ssl_trusted_certificate = '/etc/ssl/certs/ca-certificates.crt',
  Optional[String]                      $resolver               = undef,
  String                                $component_version      = 'crowdsec-openresty-bouncer/puppet',
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
      ensure_resource('file', '/etc/crowdsec/bouncers', {
        'ensure' => 'directory',
        'owner'  => 'root',
        'group'  => 'root',
        'mode'   => '0750',
      })
      Package['crowdsec-openresty-bouncer'] -> File['/etc/crowdsec/bouncers']

      file { $config_path:
        ensure  => file,
        owner   => 'root',
        group   => 'root',
        mode    => '0600',
        content => epp('crowdsec/openresty-bouncer.conf.epp', {
          'enabled'                => $enabled,
          'api_url'                => $api_url,
          'api_key'                => $api_key,
          'mode'                   => $mode,
          'cache_expiration'       => $cache_expiration,
          'request_timeout'        => $request_timeout,
          'update_frequency'       => $update_frequency,
          'enable_internal'        => $enable_internal,
          'ssl_verify'             => $ssl_verify,
          'bouncing_on_type'       => $bouncing_on_type,
          'fallback_remediation'   => $fallback_remediation,
          'exclude_location'       => $exclude_location,
          'ban_template_path'      => $ban_template_path,
          'redirect_location'      => $redirect_location,
          'ret_code'               => $ret_code,
          'captcha_provider'       => $captcha_provider,
          'captcha_secret_key'     => $captcha_secret_key,
          'captcha_site_key'       => $captcha_site_key,
          'captcha_template_path'  => $captcha_template_path,
          'captcha_expiration'     => $captcha_expiration,
          'appsec_url'             => $appsec_url,
          'appsec_failure_action'  => $appsec_failure_action,
          'appsec_connect_timeout' => $appsec_connect_timeout,
          'appsec_send_timeout'    => $appsec_send_timeout,
          'appsec_process_timeout' => $appsec_process_timeout,
          'always_send_to_appsec'  => $always_send_to_appsec,
          'extra_config'           => $extra_config,
        }),
        require => File['/etc/crowdsec/bouncers'],
      }
    }
  }
}
