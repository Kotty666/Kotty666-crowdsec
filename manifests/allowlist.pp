# @summary Manages a centralized CrowdSec LAPI allowlist via `cscli allowlists`.
#
# Allowlists (CrowdSec >= 1.6.8) live in the LAPI database and prevent
# decisions - including community blocklist entries - from being applied
# to the listed IPs/ranges by any bouncer connected to this LAPI. Use it
# on the LAPI host only.
#
# Entries are only added. Entries removed from `entries` stay in the
# allowlist until removed with `cscli allowlists remove <name> <value>`.
#
# @param entries        IPv4/IPv6 addresses or CIDR ranges to allow.
# @param allowlist_name Name of the allowlist; defaults to the resource title.
# @param description    Description stored with the allowlist.
# @param comment        Comment stored with each entry.
# @param cscli_path     Path to the cscli binary.
#
# @example Allow office networks
#   crowdsec::allowlist { 'office':
#     entries => ['192.0.2.10', '2001:db8::/48'],
#   }
define crowdsec::allowlist (
  Array[Stdlib::IP::Address]     $entries,
  Pattern[/\A[A-Za-z0-9_.-]+\z/] $allowlist_name = $title,
  Pattern[/\A[^']+\z/]           $description    = 'Managed by Puppet',
  Pattern[/\A[^']+\z/]           $comment        = 'managed by puppet',
  Stdlib::Absolutepath           $cscli_path     = '/usr/bin/cscli',
) {
  exec { "crowdsec-allowlist-create-${allowlist_name}":
    command => "${cscli_path} allowlists create ${allowlist_name} --description '${description}'",
    unless  => "${cscli_path} allowlists list -o raw 2>/dev/null | cut -d, -f1 | grep -Fxq ${allowlist_name}",
    path    => ['/usr/bin', '/bin'],
    # cscli writes directly to the LAPI database; no running service needed.
    require => Package['crowdsec'],
  }

  $entries.unique.each |Stdlib::IP::Address $entry| {
    exec { "crowdsec-allowlist-${allowlist_name}-${entry}":
      command => "${cscli_path} allowlists add ${allowlist_name} ${entry} --comment '${comment}'",
      unless  => "${cscli_path} allowlists inspect ${allowlist_name} -o raw 2>/dev/null | cut -d, -f3 | grep -Fxq ${entry}",
      path    => ['/usr/bin', '/bin'],
      require => Exec["crowdsec-allowlist-create-${allowlist_name}"],
    }
  }
}
