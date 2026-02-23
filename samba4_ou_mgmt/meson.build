gtkmm_dep = dependency('gtkmm-3.0', required: true)
ldap_dep = dependency('ldap', required: true)

executable(
  'samba4_ou_mgmt',
  'ou_mgmt.cpp',
  dependencies: [gtkmm_dep, ldap_dep],
  install: true
)
