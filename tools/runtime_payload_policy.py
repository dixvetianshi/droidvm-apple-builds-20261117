"""Select deployable VMM runtime records without rewriting their build provenance.

The AOSP collection can include link-time stubs. Android linker namespace calls
must resolve to the phone's runtime implementation, not a collected RET stub.
This policy is shared by CI collection, APK asset merging and support packaging.
"""

from pathlib import PurePosixPath
import re


EXCLUDED_LINK_STUB_NAMES = frozenset({"libdl_android.so"})
RUNTIME_PAYLOAD_POLICY_SOURCE = (
    "tools/runtime_payload_policy.py: local Android linker-stub exclusion; "
    "libdl_android.so must come from the Android platform runtime"
)


def select_runtime_members(members):
    """Return separate deployable/excluded copies of a recorded runtime map.

    The original map remains the record of what that build collected. Even an
    excluded entry must have a valid identity; filtering does not hide malformed
    source metadata or authorize files outside the crosvm/library allowlist.
    """
    if not isinstance(members, dict):
        raise ValueError("The completed build must own a runtime file map")
    selected = {}
    excluded = {}
    for name, digest in members.items():
        if not isinstance(name, str) or "\\" in name:
            raise ValueError("The runtime map contains an invalid member path")
        path = PurePosixPath(name)
        if path.as_posix() != name or ".." in path.parts or path.is_absolute():
            raise ValueError("The runtime map contains an invalid member path")
        if not (name == "runtime/usr/bin/crosvm"
                or path.parent == PurePosixPath("runtime/usr/lib") and path.suffix == ".so"):
            raise ValueError("The runtime map contains a member outside the deployment allowlist")
        if not isinstance(digest, str) or re.fullmatch(r"[0-9a-f]{64}", digest) is None:
            raise ValueError("The runtime map contains an invalid digest")
        target = excluded if path.name in EXCLUDED_LINK_STUB_NAMES else selected
        target[name] = digest
    if "runtime/usr/bin/crosvm" not in selected:
        raise ValueError("The runtime map must contain the completed crosvm executable")
    return selected, excluded
