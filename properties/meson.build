plugin_sources = files(
  'nm-openvpn-editor-plugin.c',
  'nm-openvpn-editor-plugin.h',
  'import-export.c',
  'import-export.h',
)

library('nm-vpn-plugin-openvpn', plugin_sources,
  c_args: [
    # dladdr()
    '-D_GNU_SOURCE',
    '-DNETWORKMANAGER_COMPILATION=NM_NETWORKMANAGER_COMPILATION_LIB_BASE',
  ],
  dependencies: [
    gmodule,
    plugin_utils_dep,
  ],
  install: true,
  install_dir: get_option('libdir') / 'NetworkManager',
  link_args: [
    '-Wl,--version-script,@0@'.format(meson.current_source_dir() / 'libnm-vpn-plugin-openvpn.ver'),
  ],
)

editor_sources = files(
  'nm-openvpn-editor.c',
  'nm-openvpn-editor.h',
)
editor_sources_gtk3 = [
  editor_sources,
  gnome.compile_resources('resources', 'gresource.xml',
    source_dir: '.',
  ),
]

library('nm-vpn-plugin-openvpn-editor', editor_sources_gtk3,
  c_args: [
    '-DNETWORKMANAGER_COMPILATION=NM_NETWORKMANAGER_COMPILATION_LIB_EDITOR',
  ],
  dependencies: [
    gtk3,
    libnma,
    utils_dep,
  ],
  install: true,
  install_dir: get_option('libdir') / 'NetworkManager',
  link_args: [
    '-Wl,--version-script,@0@'.format(meson.current_source_dir() / 'libnm-vpn-plugin-openvpn-editor.ver'),
  ],
)

editor_sources_gtk4 = [
  editor_sources,
  gnome.compile_resources('resources-gtk4', 'gresource.xml',
    dependencies: [
      configure_file(
        capture: true,
        command: ['grep', '-v', 'can-default', '@INPUT@'],
        input: configure_file(
          capture: true,
          command: [gtk4_builder_tool, 'simplify', '--3to4', '@INPUT@'],
          input: 'nm-openvpn-dialog.ui',
          output: 'nm-openvpn-dialog.3to4.ui',
        ),
        output: 'nm-openvpn-dialog.ui',
      )
    ],
    source_dir: meson.current_build_dir(),
  ),
]
library('nm-gtk4-vpn-plugin-openvpn-editor', editor_sources_gtk4,
  c_args: [
    '-DNETWORKMANAGER_COMPILATION=NM_NETWORKMANAGER_COMPILATION_LIB_EDITOR',
  ],
  dependencies: [
    gtk4,
    libnma_gtk4,
    utils_dep,
  ],
  install: true,
  install_dir: get_option('libdir') / 'NetworkManager',
  link_args: [
    '-Wl,--version-script,@0@'.format(meson.current_source_dir() / 'libnm-vpn-plugin-openvpn-editor.ver'),
  ],
)
