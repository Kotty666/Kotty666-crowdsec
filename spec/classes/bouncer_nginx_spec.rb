# frozen_string_literal: true

require 'spec_helper'

describe 'crowdsec::bouncer::nginx' do
  on_supported_os.each do |os, os_facts|
    context "on #{os}" do
      let(:facts) { os_facts }

      it { is_expected.to compile.with_all_deps }

      it { is_expected.to contain_package('crowdsec-nginx-bouncer') }

      it { is_expected.to contain_file('/etc/crowdsec/bouncers/crowdsec-nginx-bouncer.conf.local') }
    end
  end
end
