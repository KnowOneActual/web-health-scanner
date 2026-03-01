from .base import registry
from .plugins import (
    TechStackScanner,
    PageSpeedScanner,
    SecurityHeadersScanner,
    LinkCheckerScanner,
    DNSScanner,
    NmapScanner,
    TestSSLScanner
)

# Register default plugins
registry.register(TechStackScanner())
registry.register(PageSpeedScanner())
registry.register(SecurityHeadersScanner())
registry.register(LinkCheckerScanner())
registry.register(DNSScanner())
registry.register(NmapScanner())
registry.register(TestSSLScanner())
