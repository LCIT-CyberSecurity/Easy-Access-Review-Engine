FROM debian:13-slim@sha256:d7e12182ce18b85b93007c1dedf31f2d29e01ccf3182cc4017c709b6259bc132

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        acl \
        coreutils \
        passwd \
        python3 \
        util-linux \
    && apt-get clean \
    && find /var/lib/apt/lists -type f -delete

WORKDIR /opt/crashtests-crm
