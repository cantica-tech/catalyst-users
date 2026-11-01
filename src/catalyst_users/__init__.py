"""A facade to any identity provider: users, groups, roles and sign-in (Keycloak built in, others registered).

The core (every module but `fastapi_auth`) imports only the standard library
(env-RUNTIME-000002), so that catalyst can vendor it into its single-file CLI.
"""

__version__ = "0.11.1"
