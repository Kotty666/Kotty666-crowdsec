# @summary Manages an acquisition source file for log ingestion.
#
# @param filenames List of log file paths to ingest.
# @param type Acquisition type used by CrowdSec parsers.
define crowdsec::acquisition::file (
  Array[String] $filenames,
  String $type = 'nginx',
) {
  file { "/etc/crowdsec/acquis.d/${title}.yaml":
    ensure  => file,
    owner   => 'root',
    group   => 'root',
    mode    => '0644',
    content => epp('crowdsec/acquisition-file.yaml.epp', {
      'filenames' => $filenames,
      'type'      => $type,
    }),
    notify  => Service['crowdsec'],
  }
}
