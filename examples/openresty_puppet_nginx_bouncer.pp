# OpenResty managed via puppet-nginx plus CrowdSec OpenResty bouncer.
#
# The important bit is that the CrowdSec Lua hook is also a Puppet-managed file
# in a directory included by the nginx/openresty http context. This keeps the
# hook from being removed when puppet-nginx uses confd_purge => true.

class { 'nginx':
  confd_purge => true,
}

class { 'crowdsec::bouncer::openresty':
  api_url              => 'http://crowdsec-lapi.example.com:8080',
  api_key              => 'REPLACE_WITH_LONG_RANDOM_KEY',
  mode                 => 'stream',
  manage_nginx_snippet => true,
  nginx_snippet_path   => '/etc/nginx/conf.d/crowdsec_openresty.conf',
}

# Keep your existing nginx::resource::server / nginx::resource::location
# definitions unchanged. The bouncer runs from the http-context Lua hook above.
