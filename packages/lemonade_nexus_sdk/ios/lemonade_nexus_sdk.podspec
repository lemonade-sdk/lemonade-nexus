require 'json'
require 'digest'
require 'net/http'
require 'tmpdir'

# The XCFramework comes from scripts/build-sdk-mobile.sh (a local build) or,
# when it is missing, from the release archive pinned in native/manifest.json.
framework_dir = File.join(__dir__, 'Frameworks')
framework = File.join(framework_dir, 'lemonade_nexus_sdk.xcframework')
unless File.directory?(framework)
  manifest = JSON.parse(File.read(File.join(__dir__, '..', 'native', 'manifest.json')))
  entry = manifest['ios']
  if entry['sha256'].to_s.empty?
    raise "lemonade_nexus_sdk: no iOS archive is published for #{manifest['version']}. " \
          'Build it with scripts/build-sdk-mobile.sh in lemonade-nexus.'
  end
  url = URI("#{manifest['base_url']}/#{entry['file']}")
  body = nil
  5.times do
    response = Net::HTTP.get_response(url)
    if response.is_a?(Net::HTTPRedirection)
      url = URI(response['location'])
      next
    end
    raise "lemonade_nexus_sdk: download of #{url} failed (#{response.code})" unless response.is_a?(Net::HTTPSuccess)
    body = response.body
    break
  end
  raise 'lemonade_nexus_sdk: too many redirects' if body.nil?
  actual = Digest::SHA256.hexdigest(body)
  raise "lemonade_nexus_sdk: #{entry['file']} has SHA-256 #{actual}, expected #{entry['sha256']}" if actual != entry['sha256']
  Dir.mktmpdir do |tmp|
    zip = File.join(tmp, entry['file'])
    File.binwrite(zip, body)
    FileUtils.mkdir_p(framework_dir)
    system('ditto', '-x', '-k', zip, framework_dir, exception: true)
  end
end

Pod::Spec.new do |s|
  s.name             = 'lemonade_nexus_sdk'
  s.version          = '0.9.8'
  s.summary          = 'Lemonade Nexus client SDK for iOS.'
  s.description      = 'The Lemonade Nexus client SDK as a dynamic framework, loaded through Dart FFI.'
  s.homepage         = 'https://github.com/lemonade-sdk/lemonade-nexus'
  s.license          = { :type => 'MIT', :file => '../../../LICENSE' }
  s.author           = { 'Lemonade Nexus' => 'https://github.com/lemonade-sdk/lemonade-nexus' }
  s.source           = { :path => '.' }
  s.platform         = :ios, '15.0'
  s.vendored_frameworks = 'Frameworks/lemonade_nexus_sdk.xcframework'
  s.dependency 'Flutter'
  s.pod_target_xcconfig = { 'DEFINES_MODULE' => 'YES' }
end
