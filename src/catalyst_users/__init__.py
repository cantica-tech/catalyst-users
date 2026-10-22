"""Users, groups and roles from Keycloak over standard OIDC.

The core (every module but `fastapi_auth`) imports only the standard library
(env-RUNTIME-000002), so that catalyst can vendor it into its single-file CLI.
"""

__version__ = "0.1.0"
