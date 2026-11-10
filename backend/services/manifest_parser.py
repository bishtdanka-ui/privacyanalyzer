"""
Manifest Parser Service Shim
Re-exports the core secure AndroidManifestParser from backend.manifest_parser
for clean backward compatibility across existing services and tests.
"""

from backend.manifest_parser import (
    AndroidManifestParser,
    ManifestParser,
    ManifestParseError,
    ManifestSecurityError,
    XMLSizeLimitExceededError,
    ANDROID_NS,
    ANDROID_NS_PREFIX,
    VALID_PERMISSION_TAGS,
    KNOWN_MANIFEST_TAGS,
    MAX_MANIFEST_SIZE_BYTES
)

__all__ = [
    "AndroidManifestParser",
    "ManifestParser",
    "ManifestParseError",
    "ManifestSecurityError",
    "XMLSizeLimitExceededError",
    "ANDROID_NS",
    "ANDROID_NS_PREFIX",
    "VALID_PERMISSION_TAGS",
    "KNOWN_MANIFEST_TAGS",
    "MAX_MANIFEST_SIZE_BYTES"
]
