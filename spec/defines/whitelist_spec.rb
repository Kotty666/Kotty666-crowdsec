# frozen_string_literal: true

require 'spec_helper'

describe 'crowdsec::whitelist' do
  let(:title) { 'crawler' }
  let(:pre_condition) { 'include crowdsec::engine' }
  let(:file) { '/etc/crowdsec/parsers/s02-enrich/puppet-whitelist-crawler.yaml' }

  context 'with plain ips and ranges' do
    let(:params) { { ips: ['192.0.2.10', '198.51.100.0/24', '2001:db8::/48'] } }

    it { is_expected.to compile.with_all_deps }

    it 'renders its own parser file' do
      is_expected.to contain_file(file).with(
        ensure: 'file',
        owner: 'root',
        group: 'root',
        mode: '0644',
      ).that_requires('File[/etc/crowdsec/parsers/s02-enrich]')
        .that_notifies('Service[crowdsec]')
    end

    it 'uses a parser name per whitelist' do
      is_expected.to contain_file(file)
        .with_content(%r{^name: crowdsec/puppet-whitelist-crawler$})
        .with_content(%r{^  reason: "puppet-managed whitelist crawler"$})
        .with_content(%r{managed by Puppet \(crowdsec::whitelist\[crawler\]\)})
    end

    it 'sorts addresses into ip and ranges into cidr' do
      is_expected.to contain_file(file)
        .with_content(%r{  ip:\n    - "192\.0\.2\.10"\n})
        .with_content(%r{  cidr:\n    - "198\.51\.100\.0/24"\n    - "2001:db8::/48"\n})
        .without_content(%r{expression:})
    end
  end

  context 'with a condition' do
    let(:params) do
      {
        ips: ['192.0.2.10', '192.0.2.11', '198.51.100.0/24'],
        condition: "evt.Parsed.http_user_agent contains 'ExampleBot'",
        reason: 'ExampleBot crawler (ip + user agent)',
      }
    end

    it { is_expected.to compile.with_all_deps }

    it 'folds the addresses into one expression combined with the condition' do
      is_expected.to contain_file(file)
        .with_content(%r{  expression:\n    - "\(evt\.Meta\.source_ip in \['192\.0\.2\.10', '192\.0\.2\.11'\] \|\| IpInRange\(evt\.Meta\.source_ip, '198\.51\.100\.0/24'\)\) && \(evt\.Parsed\.http_user_agent contains 'ExampleBot'\)"\n})
        .with_content(%r{^  reason: "ExampleBot crawler \(ip \+ user agent\)"$})
    end

    it 'does not list the addresses unconditionally' do
      is_expected.to contain_file(file)
        .without_content(%r{^  ip:$})
        .without_content(%r{^  cidr:$})
    end
  end

  context 'with a condition and only ranges' do
    let(:params) { { ips: ['198.51.100.0/24'], condition: 'true' } }

    it 'omits the empty address list' do
      is_expected.to contain_file(file)
        .with_content(%r{    - "\(IpInRange\(evt\.Meta\.source_ip, '198\.51\.100\.0/24'\)\) && \(true\)"})
    end
  end

  context 'with expressions only' do
    let(:params) { { expressions: ["evt.Parsed.http_path startsWith '/health'"] } }

    it do
      is_expected.to contain_file(file)
        .with_content(%r{  expression:\n    - "evt\.Parsed\.http_path startsWith '/health'"\n})
    end
  end

  context 'with a custom whitelist_name' do
    let(:params) { { whitelist_name: 'bots', ips: ['192.0.2.10'] } }

    it { is_expected.to contain_file('/etc/crowdsec/parsers/s02-enrich/puppet-whitelist-bots.yaml') }
  end

  context 'with ensure absent' do
    let(:params) { { ensure: 'absent' } }

    it { is_expected.to contain_file(file).with_ensure('absent').that_notifies('Service[crowdsec]') }
  end

  context 'without ips and expressions' do
    it { is_expected.to compile.and_raise_error(%r{set ips and/or expressions}) }
  end

  context 'with a condition but without ips' do
    let(:params) { { condition: 'true', expressions: ['true'] } }

    it { is_expected.to compile.and_raise_error(%r{condition requires ips}) }
  end

  context 'without crowdsec::engine' do
    let(:pre_condition) { '' }
    let(:params) { { ips: ['192.0.2.10'] } }

    it { is_expected.to compile.with_all_deps }
    it { is_expected.to contain_file(file).with_require(nil).with_notify(nil) }
  end
end
