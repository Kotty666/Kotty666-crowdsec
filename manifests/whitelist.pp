# @summary Manages a named enrichment-stage CrowdSec parser whitelist.
#
# Each resource renders its own parser file
# `/etc/crowdsec/parsers/s02-enrich/puppet-whitelist-<name>.yaml`, so whitelists
# for different purposes stay separate and show up under their own parser name
# (`crowdsec/puppet-whitelist-<name>`) in `cscli explain` and in the logs.
# Events matching the whitelist are dropped before any alert or decision is
# created. It complements the global `crowdsec::whitelists` list, which keeps
# working unchanged.
#
# CrowdSec ORs the `ip`, `cidr` and `expression` entries of a whitelist. To
# whitelist addresses only when an additional condition holds (for example a
# crawler that must also send its user agent), set `condition`: the addresses
# are then folded into a single expression
# `(<source ip matches>) && (<condition>)` instead of being listed as plain
# `ip`/`cidr` entries.
#
# @param ensure
#   Whether the whitelist parser file is present or removed.
# @param whitelist_name
#   Name of the whitelist, used in the file and parser name. Defaults to the title.
# @param ips
#   IPv4/IPv6 addresses or CIDR ranges. Write addresses in canonical form, they
#   are compared as strings when `condition` is set.
# @param condition
#   Optional CrowdSec expression that must be true in addition to the source
#   address matching `ips`. Requires `ips`.
# @param expressions
#   Additional CrowdSec expressions, each whitelisting on its own (ORed with the
#   rest of the whitelist).
# @param reason
#   Reason recorded by CrowdSec for whitelisted events.
# @param description
#   Description of the parser.
#
# @example Whitelist a monitoring network
#   crowdsec::whitelist { 'monitoring':
#     ips => ['192.0.2.0/28', '2001:db8::10'],
#   }
#
# @example Whitelist crawler addresses only together with the crawler user agent
#   crowdsec::whitelist { 'crawler':
#     ips       => ['192.0.2.10', '192.0.2.11'],
#     condition => "evt.Parsed.http_user_agent contains 'ExampleBot'",
#     reason    => 'ExampleBot crawler (ip + user agent)',
#   }
define crowdsec::whitelist (
  Enum['present', 'absent']      $ensure         = 'present',
  Pattern[/\A[A-Za-z0-9_.-]+\z/] $whitelist_name = $title,
  Array[Stdlib::IP::Address]     $ips            = [],
  Optional[String[1]]            $condition      = undef,
  Array[String[1]]               $expressions    = [],
  String[1]                      $reason         = "puppet-managed whitelist ${title}",
  String[1]                      $description    = "Puppet-managed whitelist ${title} (crowdsec::whitelist)",
) {
  $file = "/etc/crowdsec/parsers/s02-enrich/puppet-whitelist-${whitelist_name}.yaml"

  if defined(Class['crowdsec::engine']) {
    $file_require = File['/etc/crowdsec/parsers/s02-enrich']
    $file_notify  = Service['crowdsec']
  } else {
    $file_require = undef
    $file_notify  = undef
  }

  if $ensure == 'absent' {
    file { $file:
      ensure => absent,
      notify => $file_notify,
    }
  } else {
    if empty($ips) and empty($expressions) {
      fail("crowdsec::whitelist[${title}]: set ips and/or expressions")
    }
    if $condition and empty($ips) {
      fail("crowdsec::whitelist[${title}]: condition requires ips")
    }

    $addresses = $ips.unique.filter |$entry| { $entry =~ Stdlib::IP::Address::Nosubnet }
    $ranges    = $ips.unique.filter |$entry| { $entry !~ Stdlib::IP::Address::Nosubnet }

    if $condition {
      $address_match = empty($addresses) ? {
        true    => [],
        default => ["evt.Meta.source_ip in [${addresses.map |$a| { "'${a}'" }.join(', ')}]"],
      }
      $range_match = $ranges.map |$r| { "IpInRange(evt.Meta.source_ip, '${r}')" }
      $source_match = ($address_match + $range_match).join(' || ')

      $list_ips    = []
      $list_cidrs  = []
      $list_exprs  = ["(${source_match}) && (${condition})"] + $expressions
    } else {
      $list_ips    = $addresses
      $list_cidrs  = $ranges
      $list_exprs  = $expressions
    }

    file { $file:
      ensure  => file,
      owner   => 'root',
      group   => 'root',
      mode    => '0644',
      content => epp('crowdsec/whitelists.yaml.epp', {
        'ips'         => $list_ips,
        'cidrs'       => $list_cidrs,
        'expressions' => $list_exprs,
        'parser_name' => "crowdsec/puppet-whitelist-${whitelist_name}",
        'description' => $description,
        'reason'      => $reason,
        'managed_by'  => "crowdsec::whitelist[${title}]",
      }),
      require => $file_require,
      notify  => $file_notify,
    }
  }
}
