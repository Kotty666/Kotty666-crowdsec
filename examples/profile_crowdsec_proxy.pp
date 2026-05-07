# Example wrapper profile for a reverse-proxy host using this module.
#
# Usage:
# - include this profile from your role
# - steer parameters through Hiera (e.g. profile::crowdsec_proxy::*)
#
# @param bouncer_api_key API key for the nginx bouncer to authenticate against the LAPI.
# @param collections List of CrowdSec collections to install.
# @param whitelists List of IP ranges or expressions to whitelist globally.
# @param nginx_log_files Log files to feed into the CrowdSec acquisition pipeline.
# @param enable_appsec Whether to enable the CrowdSec AppSec component.
# @param appsec_listen_addr Address and port the AppSec component listens on.
# @param bouncer_api_url URL of the CrowdSec LAPI the nginx bouncer connects to.
# @param bouncer_mode Mode for the nginx bouncer (stream or live).
# @param console_enroll_key Optional enrollment key for the CrowdSec console.
# lint:ignore:autoloader_layout
class profile::crowdsec_proxy (
  String $bouncer_api_key,
  Array[String] $collections = [
    'crowdsecurity/nginx',
    'crowdsecurity/http-cve',
    'crowdsecurity/whitelist-good-actors',
  ],
  Array[String] $whitelists = [],
  Array[String] $nginx_log_files = [
    '/var/log/nginx/access.log',
    '/var/log/nginx/error.log',
  ],
  Boolean $enable_appsec = true,
  String $appsec_listen_addr = '127.0.0.1:7422',
  String $bouncer_api_url = 'http://127.0.0.1:8080',
  Enum['stream', 'live'] $bouncer_mode = 'stream',
  Optional[String] $console_enroll_key = undef,
) {
  class { 'crowdsec':
    collections        => $collections,
    whitelists         => $whitelists,
    console_enroll_key => $console_enroll_key,
  }

  crowdsec::acquisition::file { 'nginx':
    filenames => $nginx_log_files,
    type      => 'nginx',
  }

  class { 'crowdsec::bouncer::nginx':
    api_url => $bouncer_api_url,
    api_key => $bouncer_api_key,
    mode    => $bouncer_mode,
  }

  if $enable_appsec {
    class { 'crowdsec::appsec':
      listen_addr => $appsec_listen_addr,
    }
  }
}
# lint:endignore
