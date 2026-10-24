# frozen_string_literal: true

require 'spec_helper'

describe 'crowdsec::allowlist' do
  let(:title) { 'trusted' }
  let(:pre_condition) { 'include crowdsec::engine' }

  context 'with IPv4 and IPv6 entries' do
    let(:params) do
      {
        entries: ['192.0.2.10', '198.51.100.0/27', '2001:db8::/48'],
        description: 'Trusted networks',
      }
    end

    it { is_expected.to compile.with_all_deps }

    it 'creates the allowlist once' do
      is_expected.to contain_exec('crowdsec-allowlist-create-trusted').with(
        command: "/usr/bin/cscli allowlists create trusted --description 'Trusted networks'",
        unless: '/usr/bin/cscli allowlists list -o raw 2>/dev/null | cut -d, -f1 | grep -Fxq trusted',
        path: ['/usr/bin', '/bin'],
        require: 'Package[crowdsec]',
      )
    end

    ['192.0.2.10', '198.51.100.0/27', '2001:db8::/48'].each do |entry|
      it "adds #{entry} idempotently" do
        is_expected.to contain_exec("crowdsec-allowlist-trusted-#{entry}").with(
          command: "/usr/bin/cscli allowlists add trusted #{entry} --comment 'managed by puppet'",
          unless: "/usr/bin/cscli allowlists inspect trusted -o raw 2>/dev/null | cut -d, -f3 | grep -Fxq #{entry}",
          path: ['/usr/bin', '/bin'],
          require: 'Exec[crowdsec-allowlist-create-trusted]',
        )
      end
    end
  end

  context 'with an invalid entry' do
    let(:params) { { entries: ['not-an-ip'] } }

    it { is_expected.to compile.and_raise_error(%r{entries}) }
  end

  context 'with an invalid allowlist name' do
    let(:title) { 'bad name;rm' }
    let(:params) { { entries: ['192.0.2.10'] } }

    it { is_expected.to compile.and_raise_error(%r{allowlist_name}) }
  end
end
