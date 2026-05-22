# frozen_string_literal: true

require 'spec_helper'

describe 'crowdsec::bouncer::nginx' do
  on_supported_os.each do |os, os_facts|
    context "on #{os}" do
      let(:facts) { os_facts }

      it { is_expected.to compile.with_all_deps }

      it { is_expected.to contain_package('crowdsec-nginx-bouncer') }

      it do
        is_expected.to contain_file('/etc/crowdsec/bouncers/crowdsec-nginx-bouncer.conf.local').with(
          ensure: 'file',
          owner: 'root',
          group: 'root',
          mode: '0600',
          require: 'File[/etc/crowdsec/bouncers]',
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

      it 'manages the nginx Lua hook by default so puppet-nginx purges do not remove the bouncer' do
        is_expected.to contain_file('/etc/nginx/conf.d/crowdsec_nginx.conf').with(
          ensure: 'file',
          owner: 'root',
          group: 'root',
          mode: '0644',
          require: 'Package[crowdsec-nginx-bouncer]',
        )
        is_expected.to contain_file('/etc/nginx/conf.d/crowdsec_nginx.conf')
          .with_content(%r{lua_shared_dict crowdsec_cache 50m;})
        is_expected.to contain_file('/etc/nginx/conf.d/crowdsec_nginx.conf')
          .with_content(%r{cs\.init\("/etc/crowdsec/bouncers/crowdsec-nginx-bouncer\.conf", "crowdsec-nginx-bouncer/puppet"\)})
        is_expected.to contain_file('/etc/nginx/conf.d/crowdsec_nginx.conf')
          .with_content(%r{access_by_lua_block})
        is_expected.to contain_file('/etc/nginx/conf.d/crowdsec_nginx.conf')
          .with_content(%r{cs\.Allow\(ngx\.var\.remote_addr\)})
        is_expected.to contain_file('/etc/nginx/conf.d/crowdsec_nginx.conf')
          .with_content(%r{lua_package_path '/usr/lib/crowdsec/lua/\?\.lua;;';})
        expected_ca = (os_facts[:os]['family'] == 'RedHat') ? '/etc/pki/tls/certs/ca-bundle.crt' : '/etc/ssl/certs/ca-certificates.crt'
        is_expected.to contain_file('/etc/nginx/conf.d/crowdsec_nginx.conf')
          .with_content(%r{lua_ssl_trusted_certificate #{Regexp.escape(expected_ca)};})
        is_expected.to contain_file_line('crowdsec-nginx-conf-d-include').with(
          path: '/etc/nginx/nginx.conf',
          line: '  include /etc/nginx/conf.d/*.conf;',
          match: '^\s*include\s+/etc/nginx/conf\.d/\*\.conf;\s*$',
          after: '^\s*http\s*\{',
          require: 'File[/etc/nginx/conf.d/crowdsec_nginx.conf]',
        )
      end

      context 'with custom nginx Lua hook settings' do
        let(:params) do
          {
            nginx_snippet_path: '/etc/nginx/conf.d/00-crowdsec.conf',
            lua_cache_size: '100m',
            resolver: 'local=on ipv6=off',
            nginx_conf_path: '/etc/nginx/custom-nginx.conf',
            nginx_conf_include: '/etc/nginx/custom-conf.d/*.conf',
            nginx_conf_include_match: '^\s*include\s+/etc/nginx/custom-conf\.d/\*\.conf;\s*$',
          }
        end

        it { is_expected.to compile.with_all_deps }

        it 'renders the overridden nginx hook settings' do
          is_expected.to contain_file('/etc/nginx/conf.d/00-crowdsec.conf')
            .with_content(%r{lua_shared_dict crowdsec_cache 100m;})
          is_expected.to contain_file('/etc/nginx/conf.d/00-crowdsec.conf')
            .with_content(%r{resolver local=on ipv6=off;})
          is_expected.to contain_file_line('crowdsec-nginx-conf-d-include').with(
            path: '/etc/nginx/custom-nginx.conf',
            line: '  include /etc/nginx/custom-conf.d/*.conf;',
            match: '^\s*include\s+/etc/nginx/custom-conf\.d/\*\.conf;\s*$',
          )
        end
      end

      context 'with manage_nginx_snippet => false' do
        let(:params) { { manage_nginx_snippet: false } }

        it { is_expected.not_to contain_file('/etc/nginx/conf.d/crowdsec_nginx.conf') }
        it { is_expected.not_to contain_file_line('crowdsec-nginx-conf-d-include') }
      end

      context 'with manage_nginx_conf_include => false' do
        let(:params) { { manage_nginx_conf_include: false } }

        it { is_expected.not_to contain_file_line('crowdsec-nginx-conf-d-include') }
      end

      context 'with manage_config => false' do
        let(:params) { { manage_config: false } }

        it { is_expected.not_to contain_file('/etc/crowdsec/bouncers/crowdsec-nginx-bouncer.conf.local') }
      end

      context 'when crowdsec::engine already manages the bouncer directory' do
        let(:pre_condition) { 'include crowdsec::engine' }

        it { is_expected.to compile.with_all_deps }
      end

      context 'with ensure => absent' do
        let(:params) { { ensure: 'absent' } }

        it { is_expected.to contain_file('/etc/nginx/conf.d/crowdsec_nginx.conf').with(ensure: 'absent') }
        it { is_expected.not_to contain_file_line('crowdsec-nginx-conf-d-include') }
        it { is_expected.to contain_file('/etc/crowdsec/bouncers/crowdsec-nginx-bouncer.conf.local').with(ensure: 'absent') }
      end
    end
  end
end
