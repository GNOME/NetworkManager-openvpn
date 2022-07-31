shared_inc = include_directories('.', '..')
utils_dep = declare_dependency(
  dependencies: [
    glib,
    libnm,
  ],
  include_directories: shared_inc,
  sources: files(
    'nm-utils/nm-shared-utils.c',
    'utils.c',
  ),
)
plugin_utils_dep = declare_dependency(
  dependencies: [
    utils_dep,
  ],
  sources: files(
    'nm-utils/nm-vpn-plugin-utils.c',
    'nm-utils/nm-vpn-plugin-utils.h',
    'nm-utils/nm-vpn-plugin-macros.h',
  ),
)
