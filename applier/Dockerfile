FROM docker:28-cli
# Shared handshake dir with the dashboard (uid 10001). 0777 so neither side needs extra capabilities.
RUN mkdir -p /applier && chown 10001:10001 /applier && chmod 0777 /applier
COPY --chmod=0555 apply.sh /usr/local/bin/apply.sh
ENTRYPOINT ["/usr/local/bin/apply.sh"]
