# frozen_string_literal: true

require 'spec_helper'

describe 'crowdsec::bouncer::openresty' do
  on_supported_os.each do |os, os_facts|
    context "on #{os}" do
      let(:facts) { os_facts }

      it { is_expected.to compile.with_all_deps }

      it { is_expected.to contain_package('crowdsec-openresty-bouncer') }

      it do
        is_expected.to contain_file('/etc/crowdsec/bouncers').with(
          ensure: 'directory',
          owner: 'root',
          group: 'root',
          mode: '0750',
        )
      end

      it do
        is_expected.to contain_file('/etc/crowdsec/bouncers/crowdsec-openresty-bouncer.conf').with(
          ensure: 'file',
          owner: 'root',
          group: 'root',
          mode: '0600',
          require: 'File[/etc/crowdsec/bouncers]',
        )
      end

      it 'renders required defaults so the bouncer is enabled and templates resolve' do
        is_expected.to contain_file('/etc/crowdsec/bouncers/crowdsec-openresty-bouncer.conf')
          .with_content(%r{^ENABLED=true$})
        is_expected.to contain_file('/etc/crowdsec/bouncers/crowdsec-openresty-bouncer.conf')
          .with_content(%r{^BAN_TEMPLATE_PATH=/var/lib/crowdsec/lua/templates/ban\.html$})
        is_expected.to contain_file('/etc/crowdsec/bouncers/crowdsec-openresty-bouncer.conf')
          .with_content(%r{^CAPTCHA_TEMPLATE_PATH=/var/lib/crowdsec/lua/templates/captcha\.html$})
        is_expected.to contain_file('/etc/crowdsec/bouncers/crowdsec-openresty-bouncer.conf')
          .with_content(%r{^MODE=stream$})
        is_expected.to contain_file('/etc/crowdsec/bouncers/crowdsec-openresty-bouncer.conf')
          .with_content(%r{^SSL_VERIFY=true$})
        is_expected.to contain_file('/etc/crowdsec/bouncers/crowdsec-openresty-bouncer.conf')
          .with_content(%r{^UPDATE_FREQUENCY=10$})
      end

      context 'with enabled => false' do
        let(:params) { { enabled: false } }

        it 'renders ENABLED=false' do
          is_expected.to contain_file('/etc/crowdsec/bouncers/crowdsec-openresty-bouncer.conf')
            .with_content(%r{^ENABLED=false$})
        end
      end

      context 'with custom template paths and tunables' do
        let(:params) do
          {
            ban_template_path: '/etc/crowdsec/templates/ban.html',
            captcha_template_path: '/etc/crowdsec/templates/captcha.html',
            cache_expiration: 5,
            request_timeout: 5000,
            update_frequency: 30,
            enable_internal: true,
            ssl_verify: false,
            redirect_location: '/blocked',
            ret_code: 403,
          }
        end

        it 'renders the overridden values' do
          is_expected.to contain_file('/etc/crowdsec/bouncers/crowdsec-openresty-bouncer.conf')
            .with_content(%r{^BAN_TEMPLATE_PATH=/etc/crowdsec/templates/ban\.html$})
          is_expected.to contain_file('/etc/crowdsec/bouncers/crowdsec-openresty-bouncer.conf')
            .with_content(%r{^CAPTCHA_TEMPLATE_PATH=/etc/crowdsec/templates/captcha\.html$})
          is_expected.to contain_file('/etc/crowdsec/bouncers/crowdsec-openresty-bouncer.conf')
            .with_content(%r{^CACHE_EXPIRATION=5$})
          is_expected.to contain_file('/etc/crowdsec/bouncers/crowdsec-openresty-bouncer.conf')
            .with_content(%r{^REQUEST_TIMEOUT=5000$})
          is_expected.to contain_file('/etc/crowdsec/bouncers/crowdsec-openresty-bouncer.conf')
            .with_content(%r{^UPDATE_FREQUENCY=30$})
          is_expected.to contain_file('/etc/crowdsec/bouncers/crowdsec-openresty-bouncer.conf')
            .with_content(%r{^ENABLE_INTERNAL=true$})
          is_expected.to contain_file('/etc/crowdsec/bouncers/crowdsec-openresty-bouncer.conf')
            .with_content(%r{^SSL_VERIFY=false$})
          is_expected.to contain_file('/etc/crowdsec/bouncers/crowdsec-openresty-bouncer.conf')
            .with_content(%r{^REDIRECT_LOCATION=/blocked$})
          is_expected.to contain_file('/etc/crowdsec/bouncers/crowdsec-openresty-bouncer.conf')
            .with_content(%r{^RET_CODE=403$})
        end
      end

      context 'with remote LAPI parameters' do
        let(:params) do
          {
            api_url: 'http://crowdsec-lapi.example.com:8080',
            api_key: 'secret-api-key',
            mode: 'stream',
            extra_config: {
              'UPDATE_FREQUENCY' => '10',
              'SSL_VERIFY' => 'true',
            },
          }
        end

        it { is_expected.to compile.with_all_deps }

        it 'renders remote bouncer settings' do
          is_expected.to contain_file('/etc/crowdsec/bouncers/crowdsec-openresty-bouncer.conf')
            .with_content(%r{API_URL=http://crowdsec-lapi.example.com:8080})
          is_expected.to contain_file('/etc/crowdsec/bouncers/crowdsec-openresty-bouncer.conf')
            .with_content(%r{API_KEY=secret-api-key})
          is_expected.to contain_file('/etc/crowdsec/bouncers/crowdsec-openresty-bouncer.conf')
            .with_content(%r{UPDATE_FREQUENCY=10})
          is_expected.to contain_file('/etc/crowdsec/bouncers/crowdsec-openresty-bouncer.conf')
            .with_content(%r{SSL_VERIFY=true})
        end
      end

      context 'with managed nginx/OpenResty Lua snippet' do
        let(:params) do
          {
            manage_nginx_snippet: true,
            nginx_snippet_path: '/etc/nginx/conf.d/crowdsec_openresty.conf',
            resolver: 'local=on ipv6=off',
          }
        end

        it { is_expected.to compile.with_all_deps }

        it 'renders the http-context Lua hook for puppet-nginx managed conf.d' do
          is_expected.to contain_file('/etc/nginx/conf.d/crowdsec_openresty.conf').with(
            ensure: 'file',
            owner: 'root',
            group: 'root',
            mode: '0644',
            require: 'Package[crowdsec-openresty-bouncer]',
          )
          is_expected.to contain_file('/etc/nginx/conf.d/crowdsec_openresty.conf')
            .with_content(%r{init_by_lua_block})
          is_expected.to contain_file('/etc/nginx/conf.d/crowdsec_openresty.conf')
            .with_content(%r{access_by_lua_block})
          is_expected.to contain_file('/etc/nginx/conf.d/crowdsec_openresty.conf')
            .with_content(%r{resolver local=on ipv6=off;})
        end
      end

      context 'when crowdsec::engine already manages the bouncer directory' do
        let(:pre_condition) { 'include crowdsec::engine' }

        it { is_expected.to compile.with_all_deps }
      end

      context 'with manage_config => false' do
        let(:params) { { manage_config: false } }

        it { is_expected.not_to contain_file('/etc/crowdsec/bouncers/crowdsec-openresty-bouncer.conf') }
      end
    end
  end
end
