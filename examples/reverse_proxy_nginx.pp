# Typical reverse proxy setup with nginx logs + nginx bouncer
include crowdsec

crowdsec::collection { 'crowdsecurity/nginx': }
crowdsec::collection { 'crowdsecurity/http-cve': }

crowdsec::acquisition::file { 'nginx':
  filenames => [
    '/var/log/nginx/access.log',
    '/var/log/nginx/error.log',
  ],
  type      => 'nginx',
}

class { 'crowdsec::bouncer::nginx':
  api_url => 'http://127.0.0.1:8080',
  api_key => 'CHANGEME_LONG_RANDOM_KEY',
  mode    => 'stream',
}
