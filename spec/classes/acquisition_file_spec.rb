# frozen_string_literal: true

require 'spec_helper'

describe 'crowdsec::acquisition::file', type: :define do
  on_supported_os.each do |os, os_facts|
    context "on #{os}" do
      let(:title) { 'nginx' }
      let(:facts) { os_facts }
      let(:pre_condition) { "service { 'crowdsec': ensure => running }" }
      let(:params) do
        {
          filenames: ['/var/log/nginx/access.log', '/var/log/nginx/error.log'],
          type: 'nginx',
        }
      end

      it { is_expected.to compile.with_all_deps }

      it { is_expected.to contain_file('/etc/crowdsec/acquis.d/nginx.yaml') }
    end
  end
end
