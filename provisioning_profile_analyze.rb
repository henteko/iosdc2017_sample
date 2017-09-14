require 'openssl'
require 'plist'

def profile_to_plist(profile_path)
  File.open(profile_path) do |profile|
    asn1 = OpenSSL::ASN1.decode(profile.read)
    plist_str = asn1.value[1].value[0].value[2].value[1].value[0].value
    plist = Plist.parse_xml plist_str.force_encoding('UTF-8')
    return plist
  end
end

def adhoc?(profile)
  !profile['Entitlements']['get-task-allow'] && profile['ProvisionsAllDevices'].nil?
end

def codesigning_identity(profile)
  profile['DeveloperCertificates'].each do |cert|
    certificate_str = cert.read
    certificate =  OpenSSL::X509::Certificate.new certificate_str
    id = OpenSSL::Digest::SHA1.new(certificate.to_der).to_s.upcase!
    # like a `$ security find-identity -v -p codesigning`
    return "#{id} \"#{certificate.subject.to_a[1][1]}\""
  end
end

profile_path = ARGV[0]
profile = profile_to_plist(profile_path)

puts "Provisioning Profile path: #{profile_path}"
puts "UUID: #{profile['UUID']}"
puts "ExpirationDate: #{profile['ExpirationDate']}"
puts "Application identifier: #{profile['Entitlements']['application-identifier']}" if profile['Entitlements']
puts "Team name: #{profile['TeamName']}"
puts "Codesigning identity : #{codesigning_identity(profile)}"
puts "Adhoc? : #{adhoc?(profile)}"
puts "UDID list: #{profile['ProvisionedDevices']}" if adhoc?(profile)
