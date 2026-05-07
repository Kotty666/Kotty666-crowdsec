# Minimal installation
# - manages CrowdSec repository
# - installs and enables CrowdSec engine service
class { 'crowdsec':
  manage_repo   => true,
  manage_engine => true,
  manage_lapi   => false,
}
