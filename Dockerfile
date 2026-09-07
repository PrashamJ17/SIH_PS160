# The analysis engine, packaged.
#
# Two properties this image is built around, both asserted by
# tests/integration/test_packaging.py:
#
#   * it runs as a non-root user, because a container that parses hostile packet
#     captures is the last thing that should hold uid 0;
#   * it ships no build toolchain, because the compiler that built numpy has no business
#     living in the runtime image of a security tool.
#
# The runtime stage installs libpango and its friends: WeasyPrint renders the PDF report
# through them, and their absence turns PDF export into a confusing import error at the
# moment a user asks for a report rather than at build time.

# ---------------------------------------------------------------------------- build ---
FROM python:3.11.13-slim-bookworm AS build

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONDONTWRITEBYTECODE=1

RUN apt-get update \
 && apt-get install -y --no-install-recommends build-essential \
 && rm -rf /var/lib/apt/lists/*

RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Dependencies resolve from the metadata alone, so they cache independently of the source.
WORKDIR /src
COPY pyproject.toml ./
COPY src/ipsec_sentinel/__init__.py src/ipsec_sentinel/__init__.py
RUN pip install --no-cache-dir ".[ml,api,report]"

COPY src/ src/
COPY schemas/ schemas/
RUN pip install --no-cache-dir --no-deps .

# The wheels carry their own tests and headers; neither is reachable from the CLI, and
# together they are a substantial fraction of the image.
RUN find /opt/venv -type d -name tests -prune -exec rm -rf {} + \
 && find /opt/venv -type d -name test -prune -exec rm -rf {} + \
 && find /opt/venv -type d -name "__pycache__" -prune -exec rm -rf {} + \
 && find /opt/venv -type d -name include -path "*/site-packages/*" -prune -exec rm -rf {} + \
 && find /opt/venv -name "*.so" -exec strip --strip-unneeded {} + 2>/dev/null || true

# -------------------------------------------------------------------------- runtime ---
FROM python:3.11.13-slim-bookworm AS runtime

LABEL org.opencontainers.image.title="IPsec Sentinel" \
      org.opencontainers.image.description="Passive IPsec protocol analysis and security assessment" \
      org.opencontainers.image.source="https://github.com/PrashamJ17/SIH_PS160"

# WeasyPrint's native dependencies, and nothing else. libpcap is not here on purpose:
# this image analyses capture files, it does not capture.
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      libpango-1.0-0 libpangoft2-1.0-0 libcairo2 libgdk-pixbuf-2.0-0 libffi8 shared-mime-info \
 && rm -rf /var/lib/apt/lists/*

# A fixed high uid, so a bind-mounted output directory can be made writable predictably
# on the host without anyone reaching for `chmod 777` or `--user root`.
RUN groupadd --gid 10001 sentinel \
 && useradd --uid 10001 --gid 10001 --create-home --shell /usr/sbin/nologin sentinel

COPY --from=build /opt/venv /opt/venv
COPY --chown=sentinel:sentinel dashboard/ /opt/sentinel/dashboard/
COPY --chown=sentinel:sentinel demo/pcaps/ /opt/sentinel/demo/pcaps/

ENV PATH="/opt/venv/bin:$PATH" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    SENTINEL_DASHBOARD_ROOT=/opt/sentinel/dashboard

WORKDIR /work
RUN chown sentinel:sentinel /work

USER sentinel

# `analyse` is the verb this image exists for; `version` and `--help` still work because
# the entrypoint is the CLI itself rather than one subcommand.
ENTRYPOINT ["sentinel"]
CMD ["--help"]
