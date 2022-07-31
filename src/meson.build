executable('nm-openvpn-service', 'nm-openvpn-service.c',
  dependencies: [
    utils_dep,
  ],
  install: true,
  install_dir: get_option('libexecdir'),
  link_args: [
    '-Wl,--version-script,@0@'.format(meson.project_source_root() / 'linker-script-binary.ver'),
  ],
)
executable('nm-openvpn-service-openvpn-helper', 'nm-openvpn-service-openvpn-helper.c',
  dependencies: [
    utils_dep,
  ],
  install: true,
  install_dir: get_option('libexecdir'),
  link_args: [
    '-Wl,--version-script,@0@'.format(meson.project_source_root() / 'linker-script-binary.ver'),
  ],
)
