# freshcerts [![unlicense](https://img.shields.io/badge/un-license-green.svg?style=flat)](http://unlicense.org)

## Fork information:

This is a fork of the [freshcerts](https://github.com/myfreeweb/freshcerts) project.
I didn't want to push my needs on the original maintainer, who has a wonderfully simple architecture.  But I created this fork to:
 - Support Passenger (by requiring using memcached).
 - Enable PFX archive generation (for use with Windows).

Everything from the original freshcerts documentation applies to this fork.

#### Passenger w/memcached

Create a folder in your freshcerts directory called "public" as passenger will expect that to be the 'root' folder for any documents not handled by the webapp.

When doing "bundle install" add the parameter "--with memcached":
```bash
$ bundle install --path vendor/bundle --with memcached
```

Then make sure to add the MEMCACHED environment variable to your passenger flags.  Here's a sample nginx site config:
```nginx
server {
	listen 80;
	server_name certs.example.org;
	passenger_env_var	ACME_ENDPOINT 	"https://acme-v01.api.letsencrypt.org/";
	passenger_env_var	ADMIN_EMAIL	"me@example.org";
	passenger_env_var	DATA_ROOT	/usr/local/www/freshcerts/data;
	passenger_env_var	MEMCACHED	"localhost:11211";
	root			/usr/local/www/freshcerts/public;
	passenger_enabled	on;
	passenger_app_env	production;
```

#### PFX generation
This only works from the `freshcert-multi-client` as it's the only one which has been edited to do this step.
Add the environment variable/value `CREATE_PKCS='yes'`.  It actually doesn't matter what it's set to, just so long as it's defined.  Once the certificate is downloaded, it will go back and load the cert & key and build a PKCS12 .pfx file from them.

Example:
``` bash
$ FRESHCERTS_HOST="localhost:9393" FRESHCERTS_TOKEN="eyJ0eXAiOi..." CREATE_PKCS="yes" freshcerts-multi-client subdomain.example.com 443 && service nginx reload
```

#### Windows IIS (single-site) & Exchange servers
LetsEncrypt has had support for Exchange for a while (and obviously IIS is just another webserver).  Ruby support on Windows is definitely existing, but some of the great commands available on most unix systems (curl & tar, in particular) simply don't exist in any standard form on Windows.  It's definitely possible to add them, but it seemed simpler to me to add a gem & make assumptions about the use of the RubyInstaller.org package.

freshcerts-multi-client2 is a pure-ruby (no curl, no tar) implementation, with the added dependencies on Rubygem's TarReader, and rest-client.  Add ```--with pure_ruby_client``` to the bundler install line if you desire to use it.  (On Windows, you can get away with the RubyInstaller.org package, and then "gem install rest-client" and not use bundler at all, as all other dependencies are part of the rubyinstaller.org package.)

Included in the tree are two sample scripts, ```set_exchange_cert.rb``` and ```set_windows_cert.rb```.  With the correct token, freshcerts server, and domain(s) specified, the scripts will use the pure-ruby client to get a cert, and then through various Windows/powershell utilities check & update the security certified used by IIS or Exchange.  I haven't had a need to run multiple websites with different SSL certs on the same IIS system, so that's left as a future experiment (which I hope to never have to do).

For the IIS configuration, LetsEncrypt supports URL Redirects.  This makes it pretty easy to just redirect the .well-known path to the freshcerts server.  Add an entry (application/virtual directory) under your WebSite definition, and then set it's ```HTTP Redirect``` to the freshcerts server, eg: http://freshcerts.mydomain.org/.well-known/
I set the status code to "permanent (301)" since it is a permanent entry.  I don't know if the other code choices would work as well.

# freshcerts

![Screenshot](https://files.app.net/h02q76bXk.png)

[ACME](https://letsencrypt.github.io/acme-spec/) (currently implemented by [Let's Encrypt](https://letsencrypt.org)) is a way to automatically (re)issue TLS certificates.

Most ACME clients are designed to run on the same machine as your TLS services. 
But if you have a lot of servers, there are two problems with that:
- you either have to copy your account private key onto all of them, or register multiple accounts;
- you don't have a nice monitoring dashboard & notifications!

freshcerts solves both problems.
It runs a server that exposes a much simpler API to your servers (they'll use a tiny shell script that's pretty much `openssl | curl | tar`) and a dashboard to your system administrators.
Servers are monitored to ensure they actually use the certs issued for them.
Email notifications are sent to the admins for all errors found by monitoring and for all issued certificates.

## Installation

It's a typical Ruby app, so you'll need [Bundler](https://bundler.io):

```bash
$ git clone https://github.com/myfreeweb/freshcerts.git
$ cd freshcerts
$ bundle install --path vendor/bundle
$ mkdir data
```

Use environment variables to configure the app. Read `common.rb` to see which variables are available.
You probably should change the ACME endpoint (by default, Let's Encrypt **staging** is used, not production):

```bash
$ export ACME_ENDPOINT="https://acme-v01.api.letsencrypt.org/"
$ export ADMIN_EMAIL="support@example.com"
```

Generate a tokens key:

```bash
$ openssl ecparam -genkey -name prime256v1 -out data/tokens.key.pem
```

Generate and register an account key:

```bash
$ openssl genrsa -out data/account.key.pem 4096
$ chmod 0400 data/account.key.pem
$ bundle exec ./register-account-key
```

Run:

```bash
$ bundle exec rackup -p 9393
```

(or `bundle exec puma ...`)

In production, you'll want to configure your process manager to run it.
Set `RACK_ENV=production` there in addition to the config variables (`ACME_ENDPOINT`, etc.)

### Minimizing Memory Footprint

If you want to run freshcerts on e.g. a cheap VPS with low RAM:

- by default, the monitoring worker runs in a thread inside of the app. You can run it separately with cron:
  - set `SEPARATE_MONITORING=1` for the server process (puma/rackup);
  - put `bundle exec ruby monitoring.rb` into your crontab for every 10 minutes or so.
- run the server process under [soad](https://github.com/myfreeweb/soad)! It will start the server on demand and shut it down when it's inactive. Don't set the `time-until-stop` to something ridiculously low like 1 second, because freshcerts keeps challenges in memory.

This way, memory will only be used when there are requests to the freshcerts server or when it's doing the monitoring.

## Usage

For every domain:

Generate an auth token with `bundle exec ./generate-token`.

Configure the HTTP server to forward `/.well-known/acme-challenge/*` requests to the freshcerts server.

Configure cron to run the `freshcerts-client` script every day.

Args: domain, subject, ports (comma separated), reload command, auth token. Like this:

```
FRESHCERTS_HOST="https://certs.example.com:4333" freshcerts-client example.com /CN=example.com 443 "service nginx reload" "eyJ0eXAiOi..."
```

And figure out cert paths and file permissions :-)

### Multi-domain certificates (SAN, Subject Alternative Name)

If you want to issue a certificate for multiple domains, there's a more advanced Ruby client, use it like that:

```
FRESHCERTS_HOST="https://certs.example.com:4333" FRESHCERTS_TOKEN="eyJ0eXAiOi..." freshcerts-multi-client example.com,www.example.com 443 && service nginx reload
```

If you can't use Ruby, you can modify the shell client to support multi-domain certificates. [Set up openssl.cnf to read SAN from the environment](https://security.stackexchange.com/a/86999), modify the client to read that config section (add e.g. `-extensions san_env` to the CSR generation command) and pass the domains via that variable. For the freshcerts part (first arg), use a comma-separated list of domains instead of just one domain. Do not use `subjectAltName` as a subject field, that's a special syntax supported by *some* CAs (not Let's Encrypt!) that will turn it into real SAN fields.

## Contributing

Please feel free to submit pull requests!

By participating in this project you agree to follow the [Contributor Code of Conduct](http://contributor-covenant.org/version/1/4/).

[The list of contributors is available on GitHub](https://github.com/myfreeweb/freshcerts/graphs/contributors).

## License

This is free and unencumbered software released into the public domain.  
For more information, please refer to the `UNLICENSE` file or [unlicense.org](http://unlicense.org).
