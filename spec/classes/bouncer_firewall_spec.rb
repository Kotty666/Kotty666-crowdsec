# frozen_string_literal: true

require 'spec_helper'

describe 'crowdsec::bouncer::firewall' do
  let(:config_path) { '/etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml.local' }
  let(:config_content) { catalogue.resource('file', config_path)[:content] }

  on_supported_os.each do |os, os_facts|
    context "on #{os}" do
      let(:facts) { os_facts }

      context 'with default parameters' do
        it { is_expected.to compile.with_all_deps }

        it do
          is_expected.to contain_package('crowdsec-firewall-bouncer').with(
            ensure: 'installed',
            name: 'crowdsec-firewall-bouncer-nftables',
          )
        end

        it do
          is_expected.to contain_file('/etc/crowdsec/bouncers').with(
            ensure: 'directory',
            owner: 'root',
            group: 'root',
            mode: '0750',
          )
        end

        it do
          is_expected.to contain_file(config_path).with(
            ensure: 'file',
            owner: 'root',
            group: 'root',
            mode: '0600',
            require: 'File[/etc/crowdsec/bouncers]',
            notify: 'Service[crowdsec-firewall-bouncer]',
          )
        end

        it 'marks the config content as sensitive so the API key never shows up in diffs' do
          expect(catalogue.resource('file', config_path).sensitive_parameters).to include(:content)
        end

        it 'renders the default local overrides without an API key' do
          expect(config_content).to eq(
            <<~CONTENT,
              # #####################################################################
              # ACHTUNG: Diese Datei wird von Puppet verwaltet!
              # Manuelle Aenderungen werden beim naechsten Puppet-Lauf ueberschrieben.
              # Aenderungen bitte im Puppet-Modul 'crowdsec' vornehmen.
              #
              # WARNING: This file is managed by Puppet.
              # DO NOT EDIT manually - changes will be overwritten on the next Puppet run.
              # #####################################################################
              mode: nftables
              api_url: http://127.0.0.1:8080/
              update_frequency: 10s
              deny_action: DROP
              deny_log: true
              deny_log_prefix: "crowdsec: "
              disable_ipv6: false
            CONTENT
          )
        end

        it do
          is_expected.to contain_service('crowdsec-firewall-bouncer').with(
            ensure: 'running',
            enable: true,
            name: 'crowdsec-firewall-bouncer',
            require: 'Package[crowdsec-firewall-bouncer]',
          )
        end
      end

      context 'with a remote LAPI, API key and custom logging' do
        let(:params) do
          {
            api_url: 'https://lapi.example.com:8080/',
            api_key: sensitive('0123456789abcdef'),
            deny_log: false,
            deny_log_prefix: 'cs-drop: ',
            update_frequency: '30s',
            disable_ipv6: true,
          }
        end

        it { is_expected.to compile.with_all_deps }

        it 'renders all overrides' do
          expect(config_content).to match(%r{^api_url: https://lapi\.example\.com:8080/$})
          expect(config_content).to match(%r{^api_key: 0123456789abcdef$})
          expect(config_content).to match(%r{^update_frequency: 30s$})
          expect(config_content).to match(%r{^deny_log: false$})
          expect(config_content).to match(%r{^deny_log_prefix: "cs-drop: "$})
          expect(config_content).to match(%r{^disable_ipv6: true$})
        end
      end

      context 'with mode => iptables' do
        let(:params) { { mode: 'iptables' } }

        it { is_expected.to contain_package('crowdsec-firewall-bouncer').with_name('crowdsec-firewall-bouncer-iptables') }
        it { expect(config_content).to match(%r{^mode: iptables$}) }
      end

      context 'with ensure => absent' do
        let(:params) { { ensure: 'absent' } }

        it { is_expected.to compile.with_all_deps }
        it { is_expected.to contain_package('crowdsec-firewall-bouncer').with_ensure('absent') }
        it { is_expected.to contain_file(config_path).with_ensure('absent') }
        it { is_expected.to contain_service('crowdsec-firewall-bouncer').with(ensure: 'stopped', enable: false) }
      end

      context 'when crowdsec::engine already manages the bouncer directory' do
        let(:pre_condition) { 'include crowdsec::engine' }

        it { is_expected.to compile.with_all_deps }
      end

      context 'with an invalid api_url' do
        let(:params) { { api_url: 'not a url' } }

        it { is_expected.to compile.and_raise_error(%r{api_url}) }
      end
    end
  end
end
