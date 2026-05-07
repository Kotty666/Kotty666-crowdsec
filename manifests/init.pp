# @summary Manages the CrowdSec stack and its core components.
#
# @param manage_repo Whether to manage the CrowdSec package repository.
# @param manage_engine Whether to manage the CrowdSec engine package and service.
# @param manage_lapi Whether to manage Local API client credentials.
# @param bouncer_api_keys Map of bouncer names to API keys to register on the local LAPI.
# @param collections List of CrowdSec collections to install.
# @param parsers List of CrowdSec parsers to install.
# @param scenarios List of CrowdSec scenarios to install.
# @param postoverflows List of CrowdSec postoverflows to install.
# @param whitelists List of IP ranges or expressions to whitelist globally.
# @param console_enroll_key Optional enrollment key for the CrowdSec console.
# @param manage_nginx_acquisition Whether to manage log acquisition for Nginx.
# @param nginx_access_log Path to the Nginx access log.
# @param nginx_error_log Path to the Nginx error log.
# @param manage_hub_updates Whether to manage periodic hub update/upgrade via cron.
# @param hub_update_hour Hour at which the hub update cron runs.
# @param hub_update_minute Minute at which the hub update cron runs.
# @param hub_upgrade_force Whether to pass --force to cscli hub upgrade.
# @param cscli_path Path to the cscli binary (provided via Hiera).
class crowdsec (
  Boolean              $manage_repo              = true,
  Boolean              $manage_engine            = true,
  Boolean              $manage_lapi              = true,
  Hash[String, String] $bouncer_api_keys          = {},
  Array[String]        $collections              = [],
  Array[String]        $parsers                  = [],
  Array[String]        $scenarios                = [],
  Array[String]        $postoverflows            = [],
  Array[String]        $whitelists               = [],
  Optional[String]     $console_enroll_key       = undef,
  Boolean              $manage_nginx_acquisition = false,
  String               $nginx_access_log         = '/var/log/nginx/access.log',
  String               $nginx_error_log          = '/var/log/nginx/error.log',
  Boolean              $manage_hub_updates       = true,
  Integer              $hub_update_hour          = 4,
  Integer              $hub_update_minute        = 15,
  Boolean              $hub_upgrade_force        = false,
  String               $cscli_path               = '/usr/bin/cscli',
) {
  if $manage_repo {
    contain crowdsec::repo
  }

  if $manage_engine {
    class { 'crowdsec::engine':
      cscli_path => $cscli_path,
    }
    contain crowdsec::engine
  }

  if $manage_lapi {
    class { 'crowdsec::lapi':
      cscli_path => $cscli_path,
    }
    contain crowdsec::lapi
  }

  if !empty($bouncer_api_keys) and !$manage_engine {
    fail('crowdsec::bouncer_api_keys can only be used when crowdsec::manage_engine is true')
  }

  $bouncer_api_keys.each |String $bouncer_name, String $api_key| {
    crowdsec::bouncer::api_key { $bouncer_name:
      api_key    => $api_key,
      cscli_path => $cscli_path,
    }
  }

  $collections.each |String $collection| {
    crowdsec::collection { $collection: }
  }

  $parsers.each |String $parser| {
    crowdsec::parser { $parser: }
  }

  $scenarios.each |String $scenario| {
    crowdsec::scenario { $scenario: }
  }

  $postoverflows.each |String $postoverflow| {
    crowdsec::postoverflow { $postoverflow: }
  }

  if !empty($whitelists) {
    file { '/etc/crowdsec/whitelists.yaml':
      ensure  => file,
      owner   => 'root',
      group   => 'root',
      mode    => '0644',
      content => epp('crowdsec/whitelists.yaml.epp', { 'whitelists' => $whitelists }),
    }
  }

  if $console_enroll_key {
    if $manage_engine {
      $enroll_require = Service['crowdsec']
    } else {
      $enroll_require = undef
    }
    exec { 'crowdsec-console-enroll':
      command => "${cscli_path} console enroll ${console_enroll_key}",
      unless  => '/usr/bin/test -s /etc/crowdsec/online_api_credentials.yaml',
      require => $enroll_require,
    }
  }

  if $manage_nginx_acquisition {
    crowdsec::acquisition::file { 'nginx':
      filenames => [$nginx_access_log, $nginx_error_log],
      type      => 'nginx',
    }
  }

  if $manage_hub_updates {
    $hub_force_flag = $hub_upgrade_force ? {
      true    => ' --force',
      default => '',
    }

    if $manage_engine {
      $script_require = Package['crowdsec']
    } else {
      $script_require = undef
    }

    file { '/usr/local/sbin/crowdsec-hub-update':
      ensure  => file,
      owner   => 'root',
      group   => 'root',
      mode    => '0755',
      content => epp('crowdsec/hub-update.sh.epp', {
        'cscli_path' => $cscli_path,
        'force_flag' => $hub_force_flag,
        'logger_tag' => 'crowdsec-hub-update',
      }),
      require => $script_require,
    }

    cron { 'crowdsec-hub-update':
      ensure  => present,
      command => '/usr/local/sbin/crowdsec-hub-update 2>&1 | /usr/bin/logger -t crowdsec-hub-update',
      user    => 'root',
      hour    => $hub_update_hour,
      minute  => $hub_update_minute,
      require => File['/usr/local/sbin/crowdsec-hub-update'],
    }
  } else {
    cron { 'crowdsec-hub-update':
      ensure => absent,
    }

    file { '/usr/local/sbin/crowdsec-hub-update':
      ensure => absent,
    }
  }
}
