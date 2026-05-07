# OpenResty bouncer host
# Useful for deployments where OpenResty runs separately from the engine/LAPI
# host. The complex OpenResty/Lua config stays in the OpenResty profile; this
# module manages the CrowdSec package and bouncer component config.
include crowdsec::repo

class { 'crowdsec::bouncer::openresty':
  ensure               => 'installed',
  api_url              => 'http://crowdsec-lapi.example.com:8080',
  api_key              => 'REPLACE_WITH_LONG_RANDOM_KEY',
  mode                 => 'stream',
  manage_nginx_snippet => true,
  nginx_snippet_path   => '/etc/nginx/conf.d/crowdsec_openresty.conf',
}
