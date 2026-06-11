# @summary Manages the CrowdSec stack and its core components.
#
# @param manage_repo Whether to manage the CrowdSec package repository.
# @param manage_engine Whether to manage the CrowdSec engine package and service.
# @param manage_lapi Whether to manage Local API client credentials.
# @param bouncer_api_keys Map of bouncer names to API keys to register on the local LAPI.
# @param machine_credentials Map of machine names to passwords to register on the local LAPI for remote log processors.
# @param collections List of CrowdSec collections to install.
# @param parsers List of CrowdSec parsers to install.
# @param scenarios List of CrowdSec scenarios to install.
# @param postoverflows List of CrowdSec postoverflows to install.
# @param whitelists IPs, CIDR ranges, or CrowdSec expressions to whitelist globally. Rendered as a real enrichment-stage parser whitelist under /etc/crowdsec/parsers/s02-enrich/ and fully managed: manual edits are reverted and emptying the list removes the file.
# @param console_enroll_key Optional enrollment key for the CrowdSec console.
# @param manage_nginx_acquisition Whether to manage log acquisition for Nginx.
# @param nginx_access_log Path to the Nginx access log (used when nginx_logs and nginx_acquisitions are empty).
# @param nginx_error_log Path to the Nginx error log (used when nginx_logs and nginx_acquisitions are empty).
# @param nginx_logs Array of nginx log paths (globs supported) ingested into a single 'nginx' acquisition source. Overrides nginx_access_log/nginx_error_log when non-empty.
# @param nginx_acquisitions Hash of acquisition-source-name to array of log paths. Each entry produces a separate /etc/crowdsec/acquis.d/nginx-<name>.yaml. Takes precedence over nginx_logs.
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
  Hash[String, String] $machine_credentials       = {},
  Array[String]        $collections              = [],
  Array[String]        $parsers                  = [],
  Array[String]        $scenarios                = [],
  Array[String]        $postoverflows            = [],
  Array[String]        $whitelists               = [],
  Optional[String]     $console_enroll_key       = undef,
  Boolean              $manage_nginx_acquisition = false,
  String               $nginx_access_log         = '/var/log/nginx/access.log',
  String               $nginx_error_log          = '/var/log/nginx/error.log',
  Array[String]        $nginx_logs               = [],
  Hash[String, Array[String]] $nginx_acquisitions = {},
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

  if !empty($machine_credentials) and !$manage_engine {
    fail('crowdsec::machine_credentials can only be used when crowdsec::manage_engine is true')
  }

  $bouncer_api_keys.each |String $bouncer_name, String $api_key| {
    crowdsec::bouncer::api_key { $bouncer_name:
      api_key    => $api_key,
      cscli_path => $cscli_path,
    }
  }

  $machine_credentials.each |String $machine_name, String $password| {
    crowdsec::machine { $machine_name:
      password   => $password,
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

  # Whitelists are rendered as a genuine CrowdSec parser under
  # parsers/s02-enrich, so matching events are dropped during enrichment
  # before any alert/decision is created. The file is fully managed: anything
  # added by hand is reverted on the next run, and emptying $whitelists
  # removes the file again.

  # Drop the pre-fix location this module used to write. CrowdSec never
  # loaded it (wrong path, missing parser structure), so it was a no-op.
  file { '/etc/crowdsec/whitelists.yaml':
    ensure => absent,
  }

  $whitelist_file = '/etc/crowdsec/parsers/s02-enrich/puppet-whitelists.yaml'

  if $manage_engine {
    $whitelist_require = File['/etc/crowdsec/parsers/s02-enrich']
    $whitelist_notify  = Service['crowdsec']
  } else {
    $whitelist_require = undef
    $whitelist_notify  = undef
  }

  if empty($whitelists) {
    file { $whitelist_file:
      ensure => absent,
      notify => $whitelist_notify,
    }
  } else {
    # Sort entries into the ip / cidr / expression buckets CrowdSec expects.
    # Match real IP networks/literals only: a bare IPv4/IPv6 literal is an ip,
    # an IP literal with a '/<prefix>' suffix is a cidr, and everything else
    # (including expressions that happen to contain '/', e.g. a path literal)
    # is treated as a CrowdSec expression.
    $_ip4_re   = /\A(\d{1,3}\.){3}\d{1,3}\z/
    $_ip6_re   = /\A[0-9A-Fa-f:]*:[0-9A-Fa-f:]*\z/
    $_cidr4_re = /\A(\d{1,3}\.){3}\d{1,3}\/\d{1,2}\z/
    $_cidr6_re = /\A[0-9A-Fa-f:]*:[0-9A-Fa-f:]*\/\d{1,3}\z/
    $wl_cidr = $whitelists.filter |$entry| { $entry =~ $_cidr4_re or $entry =~ $_cidr6_re }
    $wl_ip   = $whitelists.filter |$entry| { $entry =~ $_ip4_re or $entry =~ $_ip6_re }
    $wl_expr = $whitelists.filter |$entry| {
      !($entry =~ $_cidr4_re or $entry =~ $_cidr6_re or $entry =~ $_ip4_re or $entry =~ $_ip6_re)
    }

    file { $whitelist_file:
      ensure  => file,
      owner   => 'root',
      group   => 'root',
      mode    => '0644',
      content => epp('crowdsec/whitelists.yaml.epp', {
        'ips'         => $wl_ip,
        'cidrs'       => $wl_cidr,
        'expressions' => $wl_expr,
      }),
      require => $whitelist_require,
      notify  => $whitelist_notify,
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
    if !empty($nginx_acquisitions) {
      $nginx_acquisitions.each |String $source_name, Array[String] $filenames| {
        crowdsec::acquisition::file { "nginx-${source_name}":
          filenames => $filenames,
          type      => 'nginx',
        }
      }
    } else {
      $_nginx_logs = empty($nginx_logs) ? {
        true    => [$nginx_access_log, $nginx_error_log],
        default => $nginx_logs,
      }
      crowdsec::acquisition::file { 'nginx':
        filenames => $_nginx_logs,
        type      => 'nginx',
      }
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
