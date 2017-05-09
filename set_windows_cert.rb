#!/usr/bin/env ruby
#
# This is just a script to execute commands on windows for 
# the Freshcerts client.  The idea here is to set the appropriate
# environment variables for freshcerts-multi-client to handle this
# site, then pass the approriate data to certutil to import it.

require 'openssl'

subenv = {
	'FRESHCERTS_TOKEN' => '',
	'FRESHCERTS_HOST' => 'http://localhost:9292',
	'KEYS_DIRECTORY' => 'c:\certs',
	'CREATE_PKCS' => 'true',
}
domains = [
	'specify.mydomain.com',
]
port = 443

# check that the keys directory exists.
unless Dir.exists? subenv['KEYS_DIRECTORY']
	print "Keys directory needs to be manually created: #{subenv['KEYS_DIRECTORY']}\n"
	exit -1
end

command = [
	Gem.ruby,
	File.join(Dir.getwd, 'freshcerts-multi-client2.rb'),
	domains.join(','),
	"#{port}",
]
print "Fetching new certificate...\n"
system(subenv, *command)

# get & Import the PFX file.
pfx_path = File.join(subenv['KEYS_DIRECTORY'], "#{domains.join(',')}.pfx").gsub(%r{/}) { "\\" }
if File.exists? pfx_path
	print "Adding cert with certutil.\n"
	command = [
		'certutil', '-importpfx', pfx_path,
	]
	IO.popen(command, 'r+') { |io|
		io.write "\n"
	}
end

# Get Thumbprint of the cert (just the cert, not the whole pfx)...
certfile = File.join(subenv["KEYS_DIRECTORY"], "#{domains.join(',')}.cert.fullchain.pem")
if File.exists? certfile
	print "Getting active cert's thumbprint\n"
	rawfile = File.read(certfile)
	cert = OpenSSL::X509::Certificate.new(rawfile)
	thumbprint = OpenSSL::Digest::SHA1.new(cert.to_der).to_s.upcase
	
	# Check IIS's current SSL cert
	current_thumb = nil
	add_cert = true
	data = ''
	IO.popen("netsh http show sslcert ipport=0.0.0.0:443") { |io| 
		data = io.read
	}
	lines = data.split("\n")
	lines.each do |line|
		matches = line.match(/ *Certificate Hash *: *(.*)/)
		if matches
			add_cert = false
			if matches[1] != thumbprint
				current_thumb = matches[1]
				add_cert = true
			end
		end
	end
	# Tell IIS to update the app with the new cert...
	if add_cert
		print "Removing old cert from IIS...\n"
		command = [
			"netsh",
			"http", "delete", "sslcert",
			"ipport=0.0.0.0:443",
		]
		system(*command)
		
		print "Adding new cert to IIS...\n"
		command = [
			"netsh",
			"http", "add", "sslcert",
			"ipport=0.0.0.0:443",
			"certhash=#{thumbprint}",
			"appid={00000000-0000-0000-0000-000000000000}",
		]
		system(*command)
	end
end
