FROM python:3.13-slim AS build
WORKDIR /build
COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

FROM python:3.13-slim
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1
RUN groupadd --gid 10001 app \
 && useradd --uid 10001 --gid app --no-create-home --shell /usr/sbin/nologin app \
 && mkdir -p /data /ddns /applier \
 && chown app:app /data /applier && chmod 0777 /applier \
 && rm -rf /var/lib/apt/lists/* \
 && pip uninstall -y pip setuptools wheel 2>/dev/null || true
COPY --from=build /install /usr/local
WORKDIR /srv
COPY --chown=root:root app ./app
COPY --chown=root:root --chmod=0755 entrypoint.sh /entrypoint.sh
USER 10001:10001
EXPOSE 8443
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD python -c "import os,ssl,urllib.request as u;s=os.environ.get('TLS_MODE','selfsigned')!='off';c=ssl._create_unverified_context();u.urlopen(('https' if s else 'http')+'://127.0.0.1:8443/healthz',context=c if s else None,timeout=4)" || exit 1
ENTRYPOINT ["/entrypoint.sh"]
