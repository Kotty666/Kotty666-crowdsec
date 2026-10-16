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

  context 'with local_appsec_configs' do
    let(:params) do
      {
        local_appsec_configs: {
          'local/nextcloud-upload-tuning' => {
            'on_load' => [
              { 'apply' => ['SetMaxBodySize(20971520)', 'SetBodySizeExceededAction("partial")'] },
            ],
            'on_match' => [
              { 'filter' => 'IsInBand == true', 'apply' => ["SetRemediation('captcha')"] },
            ],
          },
          'local/old' => { 'ensure' => 'absent' },
        },
      }
    end

    it { is_expected.to compile.with_all_deps }

    it do
      is_expected.to contain_file('/etc/crowdsec/appsec-configs/local-nextcloud-upload-tuning.yaml')
        .with_ensure('file')
        .with_require('File[/etc/crowdsec/appsec-configs]')
        .with_content(%r{^name: 'local/nextcloud-upload-tuning'$})
        .with_content(%r{^on_load:\n  - apply:\n      - 'SetMaxBodySize\(20971520\)'\n      - 'SetBodySizeExceededAction\("partial"\)'\n})
        .with_content(%r{^on_match:\n  - filter: 'IsInBand == true'\n    apply:\n      - 'SetRemediation\(''captcha''\)'\n})
    end

    it { is_expected.to contain_file('/etc/crowdsec/appsec-configs/local-old.yaml').with_ensure('absent') }

    it { is_expected.not_to contain_exec('crowdsec-appsec-config-local/nextcloud-upload-tuning') }

    it do
      is_expected.to contain_file('/etc/crowdsec/acquis.d/appsec.yaml')
        .with_content(%r{^appsec_configs:\n  - crowdsecurity/appsec-default\n  - local/nextcloud-upload-tuning\nlabels:})
    end
  end

  context 'without auth_timeout (default)' do
    it { is_expected.to contain_file('/etc/crowdsec/acquis.d/appsec.yaml').without_content(%r{auth_timeout}) }
  end

  context 'with auth_timeout for a remote LAPI' do
    let(:params) { { auth_timeout: '1s' } }

    it { is_expected.to compile.with_all_deps }

    it do
      is_expected.to contain_file('/etc/crowdsec/acquis.d/appsec.yaml')
        .with_content(%r{^path: /\nauth_timeout: 1s\nappsec_configs:\n})
    end
  end

  context 'with an invalid auth_timeout' do
    let(:params) { { auth_timeout: 'one second' } }

    it { is_expected.to compile.and_raise_error(%r{auth_timeout}) }
  end
end
