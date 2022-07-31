project('NetworkManager-openvpn', 'c',
  license: 'GPL-2.0-or-later',
  meson_version: '>=0.58.0',
  version: '1.8.19',
)

project_args = [
  # Needed for dladdr() and ppoll()
  '-D_GNU_SOURCE',
]

add_project_arguments(project_args,
  language: 'c',
)

# Imports
if get_option('gnome')
  gnome = import('gnome')
else
  gnome = disabler()
endif
i18n = import('i18n')

# config.h
conf = configuration_data()
conf.set_quoted('GETTEXT_PACKAGE', meson.project_name())
if get_option('gtk4')
  conf.set('GDK_VERSION_MIN_REQUIRED', 'GDK_VERSION_4_0')
  conf.set('GDK_VERSION_MAX_ALLOWED', 'GDK_VERSION_4_0')
elif get_option('gnome')
  conf.set('GDK_VERSION_MIN_REQUIRED', 'GDK_VERSION_3_4')
  conf.set('GDK_VERSION_MAX_ALLOWED', 'GDK_VERSION_3_4')
endif
conf.set('GLIB_VERSION_MIN_REQUIRED', 'GLIB_VERSION_2_34')
conf.set('GLIB_VERSION_MAX_ALLOWED', 'GLIB_VERSION_2_34')
conf.set_quoted('LIBEXECDIR', get_option('libexecdir'))
conf.set_quoted('LOCALEDIR', get_option('localedir'))
conf.set_quoted('LOCALSTATEDIR', get_option('localstatedir'))
conf.set_quoted('NM_OPENVPN_LOCALEDIR', get_option('localedir'))
conf.set('NM_VERSION_MIN_REQUIRED', 'NM_VERSION_1_8')
conf.set('NM_VERSION_MAX_ALLOWED', 'NM_VERSION_1_8')
conf.set_quoted('VERSION', meson.project_version())
configure_file(
  input: 'config.h.meson',
  output: '@BASENAME@',
  configuration: conf,
)

# Dependencies
gtk4_builder_tool = find_program('gtk4-builder-tool',
  required: get_option('gtk4'),
)

glib = dependency('glib-2.0',
  version: '>=2.34',
)
gmodule = dependency('gmodule-2.0',
  version: '>=2.34'
)

if get_option('gnome')
  gtk3 = dependency('gtk+-3.0',
    version: '>=3.4',
  )
  libnma = dependency('libnma',
    version: '>=1.8.0',
  )
else
  gtk3 = disabler()
  libnma = disabler()
endif

if get_option('gtk4')
  gtk4 = dependency('gtk4',
    version: '>=4.0',
  )
  libnma_gtk4 = dependency('libnma-gtk4',
    version: '>=1.8.33',
  )
else
  gtk4 = disabler()
  libnma_gtk4 = disabler()
endif

libnm = dependency('libnm',
  version: '>=1.7.0',
)

if get_option('gnome') or get_option('gtk4')
  secret = dependency('libsecret-1',
    version: '>=0.18',
  )
else
  secret = disabler()
endif

subdir('po')
subdir('appdata')
subdir('shared')
subdir('auth-dialog')
subdir('properties')
subdir('src')

install_data('nm-openvpn-service.conf',
  install_dir: get_option('datadir') / 'dbus-1' / 'system.d',
)

name_conf = configuration_data()
name_conf.set('LIBEXECDIR', get_option('libexecdir'))
name_conf.set('PLUGINDIR', get_option('libdir') / 'NetworkManager')
configure_file(
  configuration: name_conf,
  input: 'nm-openvpn-service.name.in',
  install: true,
  install_dir: libnm.get_variable('vpnservicedir',
    pkgconfig_define: [
      'prefix', get_option('prefix'),
    ],
  ),
  output: 'nm-openvpn-service.name',
)
