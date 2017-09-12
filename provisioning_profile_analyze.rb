require 'openssl'
require 'plist'

def profile_to_plist(profile_path)
  File.open(profile_path) do |profile|
    asn1 = OpenSSL::ASN1.decode(profile.read)
    plist_str = asn1.value[1].value[0].value[2].value[1].value[0].value
    plist = Plist.parse_xml plist_str.force_encoding('UTF-8')
    plist['Path'] = profile_path
    return plist
  end
end

def adhoc?(profile)
  !profile['Entitlements']['get-task-allow'] && profile['ProvisionsAllDevices'].nil?
end

def codesigning_identity(profile_path)
  profile = profile_to_plist profile_path

  profile['DeveloperCertificates'].each do |cert|
    certificate_str = cert.read
    certificate =  OpenSSL::X509::Certificate.new certificate_str
    id = OpenSSL::Digest::SHA1.new(certificate.to_der).to_s.upcase!
    return certificate.subject.to_s + " " + id
  end
end

profile = profile_to_plist('/path/to/embedded.mobileprovision')

puts "UUID: #{profile['UUID']}"
puts "ExpirationDate: #{profile['ExpirationDate']}"
puts "Application identifier: #{profile['Entitlements']['application-identifier']}" if profile['Entitlements']
puts "Team name: #{profile['TeamName']}"
puts "Codesigning identity : #{codesigning_identity(profile['Path'])}"
puts "Adhoc? : #{adhoc?(profile)}"
