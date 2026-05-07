# frozen_string_literal: true

require 'spec_helper'

describe 'crowdsec::bouncer::api_key' do
  let(:title) { 'openresty-proxy-01' }
  let(:pre_condition) { 'include crowdsec::engine' }
  let(:params) { { api_key: 'secret-api-key' } }

  it { is_expected.to compile.with_all_deps }

  it 'registers the bouncer idempotently with the supplied key' do
    is_expected.to contain_exec('crowdsec-bouncer-add-openresty-proxy-01').with(
      command: '/usr/bin/cscli bouncers add openresty-proxy-01 --key secret-api-key',
      unless: '/usr/bin/cscli bouncers inspect openresty-proxy-01 >/dev/null 2>&1',
      require: 'Service[crowdsec]',
    )
  end
end
