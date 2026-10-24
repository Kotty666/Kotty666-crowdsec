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

    it 'writes the credentials only once the package created /etc/crowdsec' do
      is_expected.to contain_file('/etc/crowdsec/local_api_credentials.yaml').that_requires('Package[crowdsec]')
    end

    it 'renders the credentials as sensitive content' do
      resource = catalogue.resource('file', '/etc/crowdsec/local_api_credentials.yaml')
      expect(resource.sensitive_parameters).to include(:content)
      expect(resource[:content]).to match(%r{^password: s3cr3t$})
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

  context 'with manage_config_local in agent-only mode' do
    let(:params) do
      {
        url: 'https://lapi.example.com:8080/',
        login: 'node1.example.com',
        password: 's3cr3t',
        manage_config_local: true,
        server_enabled: false,
      }
    end

    it { is_expected.to compile.with_all_deps }

    it 'disables the local API server via config.yaml.local' do
      is_expected.to contain_file('/etc/crowdsec/config.yaml.local').with(
        ensure: 'file',
        owner: 'root',
        group: 'root',
        mode: '0644',
        require: 'Package[crowdsec]',
        notify: 'Service[crowdsec]',
      ).with_content(
        <<~CONTENT,
          # #####################################################################
          # ACHTUNG: Diese Datei wird von Puppet verwaltet!
          # Manuelle Aenderungen werden beim naechsten Puppet-Lauf ueberschrieben.
          # Aenderungen bitte im Puppet-Modul 'crowdsec' vornehmen.
          #
          # WARNING: This file is managed by Puppet.
          # DO NOT EDIT manually - changes will be overwritten on the next Puppet run.
          # #####################################################################
          api:
            server:
              enable: false
        CONTENT
      )
    end
  end

  context 'with manage_config_local and TLS on a public listener' do
    let(:params) do
      {
        manage_config_local: true,
        server_listen_uri: '[::]:8080',
        server_tls_cert_file: '/etc/letsencrypt/live/lapi.example.com/fullchain.pem',
        server_tls_key_file: '/etc/letsencrypt/live/lapi.example.com/privkey.pem',
      }
    end

    it { is_expected.to compile.with_all_deps }

    it 'renders listen_uri and TLS settings' do
      is_expected.to contain_file('/etc/crowdsec/config.yaml.local').with_content(
        %r{^api:\n  server:\n    enable: true\n    listen_uri: "\[::\]:8080"\n    tls:\n      cert_file: /etc/letsencrypt/live/lapi\.example\.com/fullchain\.pem\n      key_file: /etc/letsencrypt/live/lapi\.example\.com/privkey\.pem\n\z},
      )
    end
  end

  context 'with manage_config_local and explicit Prometheus settings' do
    let(:params) do
      {
        manage_config_local: true,
        server_enabled: false,
        prometheus: {
          'enabled' => true,
          'level' => 'full',
          'listen_addr' => '127.0.0.1',
          'listen_port' => 6060,
        },
      }
    end

    it { is_expected.to compile.with_all_deps }

    it 'renders the prometheus section after the api section' do
      is_expected.to contain_file('/etc/crowdsec/config.yaml.local').with_content(
        %r{^api:\n  server:\n    enable: false\nprometheus:\n  enabled: true\n  level: full\n  listen_addr: 127\.0\.0\.1\n  listen_port: 6060\n\z},
      )
    end
  end

  context 'with an invalid Prometheus level' do
    let(:params) do
      {
        manage_config_local: true,
        prometheus: { 'enabled' => true, 'level' => 'verbose', 'listen_addr' => '127.0.0.1', 'listen_port' => 6060 },
      }
    end

    it { is_expected.to compile.and_raise_error(%r{prometheus}) }
  end

  context 'without prometheus (default)' do
    let(:params) { { manage_config_local: true } }

    it { is_expected.to contain_file('/etc/crowdsec/config.yaml.local').without_content(%r{prometheus}) }
  end

  context 'with manage_config_local, Prometheus and alert retention' do
    let(:params) do
      {
        manage_config_local: true,
        server_enabled: false,
        prometheus: { 'enabled' => true, 'level' => 'full', 'listen_addr' => '127.0.0.1', 'listen_port' => 6060 },
        db_flush: { 'max_items' => 100_000, 'max_age' => '14d' },
      }
    end

    it { is_expected.to compile.with_all_deps }

    it 'renders the db_config flush section after the prometheus section' do
      is_expected.to contain_file('/etc/crowdsec/config.yaml.local').with_content(
        %r{\nprometheus:\n  enabled: true\n  level: full\n  listen_addr: 127\.0\.0\.1\n  listen_port: 6060\ndb_config:\n  flush:\n    max_items: 100000\n    max_age: 14d\n\z},
      )
    end
  end

  context 'with only max_age in db_flush' do
    let(:params) { { manage_config_local: true, server_enabled: false, db_flush: { 'max_age' => '7d' } } }

    it 'renders only max_age' do
      is_expected.to contain_file('/etc/crowdsec/config.yaml.local').with_content(
        %r{^api:\n  server:\n    enable: false\ndb_config:\n  flush:\n    max_age: 7d\n\z},
      )
    end
  end

  context 'with an invalid db_flush max_age' do
    let(:params) { { manage_config_local: true, db_flush: { 'max_age' => '2w' } } }

    it { is_expected.to compile.and_raise_error(%r{db_flush}) }
  end

  context 'with an empty db_flush' do
    let(:params) { { manage_config_local: true, db_flush: {} } }

    it { is_expected.to contain_file('/etc/crowdsec/config.yaml.local').without_content(%r{db_config}) }
  end

  context 'without db_flush (default)' do
    let(:params) { { manage_config_local: true } }

    it { is_expected.to contain_file('/etc/crowdsec/config.yaml.local').without_content(%r{db_config}) }
  end

  context 'with manage_config_local => false (default)' do
    it { is_expected.not_to contain_file('/etc/crowdsec/config.yaml.local') }
  end

  context 'with a TLS certificate but no key' do
    let(:params) do
      {
        manage_config_local: true,
        server_tls_cert_file: '/etc/ssl/cert.pem',
      }
    end

    it { is_expected.to compile.and_raise_error(%r{server_tls_cert_file and server_tls_key_file must be set together}) }
  end
end
