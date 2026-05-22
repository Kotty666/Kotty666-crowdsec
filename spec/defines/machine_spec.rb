# frozen_string_literal: true

require 'spec_helper'

describe 'crowdsec::machine' do
  let(:title) { 'openresty-proxy-01' }
  let(:pre_condition) { 'include crowdsec::engine' }
  let(:params) { { password: 'secret-password' } }

  it { is_expected.to compile.with_all_deps }

  it 'registers the machine idempotently with the supplied password' do
    is_expected.to contain_exec('crowdsec-machine-add-openresty-proxy-01').with(
      command: '/usr/bin/cscli machines add openresty-proxy-01 --password \'secret-password\' -f - >/dev/null',
      unless: '/usr/bin/cscli machines list -o raw 2>/dev/null | cut -d, -f1 | grep -Fxq openresty-proxy-01',
      require: 'Service[crowdsec]',
    )
  end
end
