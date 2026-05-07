# frozen_string_literal: true

require 'spec_helper'

describe 'crowdsec::lapi' do
  let(:pre_condition) { 'include crowdsec::engine' }

  context 'with no credentials supplied' do
    it { is_expected.to compile.with_all_deps }

    it 'does not manage local_api_credentials.yaml' do
      is_expected.not_to contain_file('/etc/crowdsec/local_api_credentials.yaml')
    end

    it 'ships the registration check helper' do
      is_expected.to contain_file('/usr/local/sbin/crowdsec-ensure-local-watcher-registered').with(
        ensure: 'file',
        owner: 'root',
        group: 'root',
        mode: '0755',
      )
    end

    it 'self-heals the local watcher registration when missing' do
      is_expected.to contain_exec('crowdsec-register-local-watcher').with(
        command: '/usr/bin/cscli machines add --auto --force --file /etc/crowdsec/local_api_credentials.yaml',
        unless: '/usr/local/sbin/crowdsec-ensure-local-watcher-registered',
        notify: 'Service[crowdsec]',
      )
    end
  end

  context 'with managed server listen URI' do
    let(:params) do
      {
        manage_server_listen_uri: true,
        server_listen_uri: '0.0.0.0:8080',
      }
    end

    it { is_expected.to compile.with_all_deps }

    it 'updates the LAPI listen_uri in config.yaml' do
      is_expected.to contain_file_line('crowdsec-lapi-listen-uri').with(
        ensure: 'present',
        path: '/etc/crowdsec/config.yaml',
        line: '    listen_uri: 0.0.0.0:8080',
        match: '^\s*listen_uri:\s+.*$',
        notify: 'Service[crowdsec]',
      )
    end
  end

  context 'with login and password supplied' do
    let(:params) do
      {
        url: 'http://lapi.example.com:8080',
        login: 'watcher-1',
        password: 's3cr3t',
      }
    end

    it { is_expected.to compile.with_all_deps }

    it do
      is_expected.to contain_file('/etc/crowdsec/local_api_credentials.yaml').with(
        ensure: 'file',
        owner: 'root',
        group: 'root',
        mode: '0600',
        notify: 'Service[crowdsec]',
      )
    end

    it 'does not run the local watcher registration in remote LAPI mode' do
      is_expected.not_to contain_exec('crowdsec-register-local-watcher')
    end
  end

  context 'with only login supplied' do
    let(:params) { { login: 'watcher-1' } }

    it 'still does not manage the file (both must be set)' do
      is_expected.not_to contain_file('/etc/crowdsec/local_api_credentials.yaml')
    end

    it 'falls back to local LAPI self-heal' do
      is_expected.to contain_exec('crowdsec-register-local-watcher')
    end
  end
end
