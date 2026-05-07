# AppSec-enabled setup
include crowdsec
include crowdsec::appsec

crowdsec::collection { 'crowdsecurity/nginx': }
crowdsec::collection { 'crowdsecurity/appsec-generic-rules': }
crowdsec::collection { 'crowdsecurity/appsec-virtual-patching': }

crowdsec::acquisition::file { 'nginx':
  filenames => ['/var/log/nginx/access.log', '/var/log/nginx/error.log'],
  type      => 'nginx',
}

class { 'crowdsec::bouncer::nginx':
  api_url => 'http://127.0.0.1:8080',
  api_key => 'CHANGEME_LONG_RANDOM_KEY',
  mode    => 'live',
}
