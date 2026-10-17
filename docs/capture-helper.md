# Capture helper: installation, updates and permissions

Process and connection rates need packet capture and read access to other
users' `/proc/PID/fd`. nwtop keeps the terminal UI unprivileged and gives those
rights to a separate root-owned helper, `/usr/local/libexec/nwtop-collector`,
installed once by `scripts/setup-capture.sh`.

A [release archive](https://github.com/itmitalles-software/nwtop/releases)
contains prebuilt `bin/nwtop` and `bin/nwtop-collector` next to the same
scripts; there the scripts install those binaries instead of building them.
Everything else below applies unchanged.

`scripts/install.sh` runs `cargo build --release --locked`. It only replaces an
unchanged executable previously installed by that script; unrelated files,
symlinks, and modified executables are preserved.

`scripts/setup-capture.sh` also builds as your regular user. It requests
administrator authentication through `pkexec`, or `sudo` when `pkexec` is not
installed, only for installing `/usr/local/libexec/nwtop-collector`. Start both
scripts without sudo. The package installation command in the [README](../README.md#install) is separate from
this user-local build. **The administrator who authenticates trusts your
checkout or release archive:** the root phase runs this user-writable script and installs the binary
you built. It copies that build once into a root-only file without following a
symlink, verifies the digest of exactly that copy, and only then grants group
access and capabilities.

Run the UI installer again to update the UI. Repeat capture setup when updating
the helper; the UI installer never replaces the installed privileged helper.

The helper is owned by root, mode `0750`, and executable only by root and your
primary group. **Members of that group can monitor system-wide network
metadata.** Setup therefore refuses a primary group that is not your user private
group (named like your account), lists other members, or is the primary group of
another account, as with openSUSE's `users` or a directory's `domain users`. If
every member is trusted, rerun with `--allow-shared-group`. Only one group can
have access: when another group already has it, setup refuses to silently take
it over; `--reassign-group` moves access to your group and revokes the other.
Its file capabilities are `CAP_NET_RAW`, `CAP_DAC_READ_SEARCH`, and
`CAP_SYS_PTRACE`. After opening the capture socket, the capture thread drops all
capabilities; the sampling thread retains only the two needed to read
`/proc/PID/fd`. Both prevent gaining new privileges. Core dumps are disabled.

The UI has no capabilities. It starts the fixed helper over private stdin/stdout
pipes: no background service, listening port, or arbitrary file/command API.
Responses are bounded and interruptible, and the helper ends with its UI.
Containers and sandboxes can prevent capability acquisition even after setup;
nwtop reports this instead of inventing traffic measurements.

`--no-capture` explicitly bypasses the helper. An administrator can revoke access
by removing `/usr/local/libexec/nwtop-collector` and its receipt,
`/usr/local/libexec/.nwtop-collector.sha256`. If upgrading from nettop, also
remove the legacy helper and receipt listed in the [README](../README.md#upgrading-from-nettop) to revoke its access.
