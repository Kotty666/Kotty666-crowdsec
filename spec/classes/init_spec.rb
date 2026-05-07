# frozen_string_literal: true

require 'spec_helper'

describe 'crowdsec' do
  on_supported_os.each do |os, os_facts|
    context "on #{os}" do
      let(:facts) { os_facts }

      it { is_expected.to compile.with_all_deps }

      it { is_expected.to contain_class('crowdsec::repo') }

      it { is_expected.to contain_class('crowdsec::engine') }

      it { is_expected.to contain_class('crowdsec::lapi') }

      context 'with a custom top-level cscli_path' do
        let(:params) { { cscli_path: '/opt/crowdsec/bin/cscli' } }

        it 'propagates cscli_path into crowdsec::lapi self-heal exec' do
          is_expected.to contain_exec('crowdsec-register-local-watcher').with(
            command: '/opt/crowdsec/bin/cscli machines add --auto --force --file /etc/crowdsec/local_api_credentials.yaml',
          )
        end

        it 'propagates cscli_path into crowdsec::engine hub update exec' do
          is_expected.to contain_exec('crowdsec-hub-update-init').with(
            command: '/opt/crowdsec/bin/cscli hub update',
          )
        end
      end

      context 'with collections, whitelists and console enroll key' do
        let(:params) do
          {
            collections: ['crowdsecurity/nginx', 'crowdsecurity/http-cve'],
            whitelists: ['10.10.33.0/24', '10.10.34.0/24'],
            console_enroll_key: 'SECRET',
          }
        end

        it { is_expected.to compile.with_all_deps }

        it { is_expected.to contain_crowdsec__collection('crowdsecurity/nginx') }

        it { is_expected.to contain_crowdsec__collection('crowdsecurity/http-cve') }

        it { is_expected.to contain_file('/etc/crowdsec/whitelists.yaml') }

        it { is_expected.to contain_exec('crowdsec-console-enroll') }
      end

      context 'with bouncer API keys' do
        let(:params) do
          {
            bouncer_api_keys: {
              'openresty-proxy-01' => 'secret-api-key',
            },
          }
        end

        it { is_expected.to compile.with_all_deps }

        it 'registers the bouncer key on the local LAPI' do
          is_expected.to contain_crowdsec__bouncer__api_key('openresty-proxy-01').with(
            api_key: 'secret-api-key',
            cscli_path: '/usr/bin/cscli',
          )
        end
      end

      context 'hub update wrapper' do
        it { is_expected.to contain_file('/usr/local/sbin/crowdsec-hub-update').with(ensure: 'file', mode: '0755') }

        it do
          is_expected.to contain_cron('crowdsec-hub-update').with(
            ensure: 'present',
            command: '/usr/local/sbin/crowdsec-hub-update 2>&1 | /usr/bin/logger -t crowdsec-hub-update',
            user: 'root',
            hour: 4,
            minute: 15,
          )
        end
      end

      context 'with manage_hub_updates => false' do
        let(:params) { { manage_hub_updates: false } }

        it { is_expected.to contain_cron('crowdsec-hub-update').with(ensure: 'absent') }

        it { is_expected.to contain_file('/usr/local/sbin/crowdsec-hub-update').with(ensure: 'absent') }
      end

      context 'with parsers, scenarios and postoverflows' do
        let(:params) do
          {
            parsers: ['crowdsecurity/nginx-logs'],
            scenarios: ['crowdsecurity/http-bf'],
            postoverflows: ['crowdsecurity/rdns'],
          }
        end

        it { is_expected.to compile.with_all_deps }

        it { is_expected.to contain_crowdsec__parser('crowdsecurity/nginx-logs') }

        it { is_expected.to contain_crowdsec__scenario('crowdsecurity/http-bf') }

        it { is_expected.to contain_crowdsec__postoverflow('crowdsecurity/rdns') }
      end
    end
  end
end
