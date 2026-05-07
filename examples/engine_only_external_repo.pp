# Engine-only installation when repository is managed externally
class { 'crowdsec':
  manage_repo   => false,
  manage_engine => true,
  manage_lapi   => false,
}
