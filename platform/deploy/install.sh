#!/usr/bin/env bash
# The commercial license server is not part of this tree.
# Install the node from the release tarball:
#   tar -xzf dist/connector-os-*-linux.tar.gz
#   cd connector-os-*/
#   sudo ./install.sh
#   sudo systemctl enable --now connector-platform
set -euo pipefail
echo "install.sh: there is no license server in this build. Use the release-tarball install." >&2
exit 2
