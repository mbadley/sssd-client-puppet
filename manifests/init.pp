class sssd-client {
	group { "admins":
		gid => 1000,
		ensure => "present",
	}
	file {'/etc/sssd/ldap.XXX.pem':
		source => "puppet:///modules/sssd-client/ldap.XXX.pem",
		ensure => present,
		owner => "root",
		group => "root",
		mode  => "400"
	} ->
	class { 'sssd':
		mkhomedir     => enabled,
		config        => {
			'domain/LDAP' => {
				'auth_provider' => 'ldap',
				'debug_level' => '9',
				'id_provider' => 'ldap',
				'auth_provider' => 'ldap',
				'chpass_provider' => 'ldap',
				'access_provider' => 'ldap',
				'cache_credentials' => 'true',
				'ldap_schema' => 'rfc2307bis',
				'cache_credentials' => 'true',
				'enumerate' => 'true',
				'entry_cache_timeout' => '6000',
				'ldap_id_use_start_tls' => 'true',
				'ldap_search_base' => 'ou=users,dc=XXX',
				'ldap_uri' => 'ldaps://ldap.XXX',
				'ldap_access_filter' => '(&(objectclass=shadowaccount)(objectclass=posixaccount))',
				'ldap_user_fullname' => 'displayName',
				'ldap_group_member' => 'uniqueMember',
				'ldap_group_object_class' => 'posixGroup',
				'ldap_group_name' => 'cn',
				'ldap_network_timeout' => '3',
				'ldap_tls_reqcert' => 'demand',
				'ldap_tls_cacert' => '/etc/sssd/ldap.XXX.pem',
				'ldap_chpass_update_last_change' => 'true',
				'ldap_pwd_policy' => 'shadow',
				'ldap_account_expire_policy' => 'shadow',
				'ldap_access_order' => 'expire, filter, authorized_service, host',
				'ldap_user_ssh_public_key' => 'sshPublicKey',
				'ldap_default_bind_dn' => 'cn=sssd,ou=services,dc=XXX',
				'ldap_default_authtok' => 'XXX',
#				'ldap_tls_cert' => '/etc/sssd/ldap.XXX.pem',
#				'ldap_tls_cert' => '/etc/pki/tls/certs/machine.cert.pem',
#				'ldap_tls_key' => '/etc/pki/tls/private/machine.key.pem',
				'ldap_sudo_search_base' => 'ou=sudo,dc=XXX',
				'sudo_provider' => 'ldap',
			},
			'sudo' => {
				debug_level => "9",
			},
			'sssd' => {
				'config_file_version' => '2',
				'debug_level' => '9',
				'reconnection_retries' => '3',
				'sbus_timeout' => '30',
				'services' => 'nss, pam, sudo, ssh',
				'domains' => 'LDAP',
			},
			'nss' => {
				'debug_level' => '9',
				'reconnection_retries' => '3',
				'filter_groups' => 'root',
				'filter_users' => 'root',
				'shell_fallback' => '/sbin/nologin',
			},
		}
	} ->
	exec { "/usr/sbin/authconfig --enablesssd --enablesssdauth --updateall --enablemkhomedir":
		unless => "/bin/grep sss /etc/pam.d/*",
	} ->
	class { 'nsswitch':
		passwd => ['files','sss'],
		group => ['files','sss'],
		shadow => ['files','sss'],
		sudoers => ['files','sss'],
	} ->
	class { 'ssh':
		server_options => {
		'AuthorizedKeysCommand' => '/usr/bin/sss_ssh_authorizedkeys',
		}
	}
}
