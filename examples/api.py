"""A FastAPI service protected by catalyst-users.

docker compose up -d
export CATALYST_USERS_SERVER=http://127.0.0.1:8080 CATALYST_USERS_API_CLIENT_SECRET=dev-only-api-secret
uv run uvicorn examples.api:app --port 8000

catalyst-users --server http://127.0.0.1:8080 login
curl -H "Authorization: Bearer $(catalyst-users --server http://127.0.0.1:8080 token)" localhost:8000/me
"""

from fastapi import Depends, FastAPI

from catalyst_users.fastapi_auth import KeycloakAuth
from catalyst_users.identity import Identity

auth = KeycloakAuth()
in_catalyst = auth.require_groups("/cantica-tech/catalyst")
app = FastAPI(title="catalyst-users example")


@app.get("/me")
def me(who: Identity = Depends(auth)) -> dict:
    return {"signer": who.signer(), "groups": who.groups, "roles": who.roles}


@app.get("/catalyst/backlog")
def backlog(who: Identity = Depends(in_catalyst)) -> dict:
    return {"for": who.username, "items": []}


@app.post("/releases", dependencies=[Depends(auth.require_roles("release-manager"))])
def release() -> dict:
    return {"released": True}
