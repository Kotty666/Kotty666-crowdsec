# frozen_string_literal: true

require 'spec_helper'

describe 'crowdsec::appsec' do
  let(:pre_condition) { 'include crowdsec::engine' }

  it { is_expected.to contain_crowdsec__appsec__config('crowdsecurity/appsec-default') }

  it do
    is_expected.to contain_exec('crowdsec-appsec-config-crowdsecurity/appsec-default').with(
      command: '/usr/bin/cscli appsec-configs install crowdsecurity/appsec-default --error',
      unless: "/usr/bin/cscli appsec-configs inspect crowdsecurity/appsec-default -o raw 2>/dev/null | /bin/grep -qE '^installed: true$'",
      require: ['Package[crowdsec]', 'Exec[crowdsec-hub-update-init]'],
    )
  end

  it do
    is_expected.to contain_file('/etc/crowdsec/acquis.d/appsec.yaml').with(
      ensure: 'file',
      owner: 'root',
      group: 'root',
      mode: '0644',
      notify: 'Service[crowdsec]',
      require: 'File[/etc/crowdsec/acquis.d]',
    )
  end

  context 'with appsec_rules' do
    let(:params) do
      {
        appsec_rules: ['crowdsecurity/base-config', 'crowdsecurity/vpatch-env-vars'],
      }
    end

    it { is_expected.to contain_crowdsec__appsec__rule('crowdsecurity/base-config') }

    it { is_expected.to contain_crowdsec__appsec__rule('crowdsecurity/vpatch-env-vars') }

    it do
      is_expected.to contain_exec('crowdsec-appsec-rule-crowdsecurity/base-config').with(
        command: '/usr/bin/cscli appsec-rules install crowdsecurity/base-config --error',
        require: ['Package[crowdsec]', 'Exec[crowdsec-hub-update-init]'],
      )
    end
  end
end
