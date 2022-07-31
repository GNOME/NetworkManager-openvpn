executable('nm-openvpn-auth-dialog', 'main.c',
  dependencies: [
    gtk3,
    libnma,
    utils_dep,
    secret,
  ],
  install: true,
  install_dir: get_option('libexecdir'),
  link_args: [
    '-Wl,--version-script,@0@'.format(meson.project_source_root() / 'linker-script-binary.ver'),
  ],
)
