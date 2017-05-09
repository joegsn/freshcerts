#!/usr/bin/env ruby
#
# This is just a script to execute commands on windows for 
# the Freshcerts client.  The idea here is to set the appropriate
# environment variables for freshcerts-multi-client to handle this
# site, then pass the approriate data to certutil to import it.
# After that, use powershell to get Exchange (2010) to use the new cert.

require 'openssl'

subenv = {
	'FRESHCERTS_TOKEN' => '',
	'FRESHCERTS_HOST' => 'http://localhost:9292',
	'KEYS_DIRECTORY' => 'c:/certs',
	'CREATE_PKCS' => 'true',
}
domains = [
	'mail.mydomain.org',
	'name2.mydomain.org',
	'autodiscover.mydomain.org',
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
	print "Checking active cert thumbprint\n"
	rawfile = File.read(certfile)
	cert = OpenSSL::X509::Certificate.new(rawfile)
	thumbprint = OpenSSL::Digest::SHA1.new(cert.to_der).to_s.upcase
	
	# Check Exchange's current SSL cert
	current_thumb = nil
	add_cert = false
	data = ''
	
	command = [
		"powershell",
		"-command", 
		"\"#{[
			". 'c:\\program files\\microsoft\\exchange server\\v14\\bin\\remoteexchange.ps1'",
			"Connect-ExchangeServer -auto",
			"Get-ExchangeCertificate"
		].join(';')}\""
	]
	IO.popen(command.join(' ')) { |io| 
		data = io.read
	}
	lines = data.split("\n")
	lines.each do |line|
		matches = line.match(/([A-F0-9]+) *IP.WS. *.*/)
		if matches
			add_cert = false
			if matches[1] != thumbprint
				current_thumb = matches[1]
				add_cert = true
			end
		end
	end
	# Tell IIS to use the new cert...
	if add_cert
		print "Assigning use of new cert...\n\tfrom #{current_thumb}\n\tto   #{thumbprint}\n"
		command = [
			"powershell",
			"-command", 
			"\"#{[
				". 'c:\\program files\\microsoft\\exchange server\\v14\\bin\\remoteexchange.ps1'",
				"Connect-ExchangeServer -auto",
				"Enable-ExchangeCertificate -Thumbprint #{thumbprint} -Services \"POP,IMAP,IIS,SMTP\" -Confirm:$false -Force"
			].join(';')}\""
		]
		IO.popen(command.join(' ')) { |io|
			# just using popen to try and hide some of the BS that powershell
			# shows.
		}
	else
		print "Current certificate is active.\n"
	end
end

