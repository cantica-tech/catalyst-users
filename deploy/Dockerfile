# The provisioning container: catalyst-users and its keycloak/ scripts, run as `deploy/provision.sh`.
# Built from the repository root (`context: ..` in compose.yaml).
FROM python:3.11-slim

RUN pip install --no-cache-dir uv \
 && useradd --create-home --uid 1000 provision

WORKDIR /opt/catalyst-users
COPY pyproject.toml uv.lock README.md ./
COPY src ./src
COPY keycloak ./keycloak
COPY deploy/provision.sh /usr/local/bin/provision.sh

RUN uv sync --frozen --no-dev --no-editable \
 && chmod +x /usr/local/bin/provision.sh \
 && chown -R provision:provision /opt/catalyst-users

USER provision
ENV PATH="/opt/catalyst-users/.venv/bin:${PATH}" \
    PYTHONPATH="/opt/catalyst-users/keycloak"

ENTRYPOINT ["/usr/local/bin/provision.sh"]
