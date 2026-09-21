FROM debian:13-slim@sha256:d7e12182ce18b85b93007c1dedf31f2d29e01ccf3182cc4017c709b6259bc132

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        ca-certificates \
        ldap-utils \
        zip \
        slapd \
        python3 \
    && mkdir -p /var/run/slapd \
    && chown openldap:openldap /var/run/slapd \
    && apt-get clean \
    && find /var/lib/apt/lists -type f -delete

WORKDIR /opt/crashtests-openldap
COPY slapd.conf /etc/ldap/slapd.conf
COPY fixture.ldif /opt/crashtests-openldap/fixture.ldif
CMD ["/bin/sh", "-c", "slapadd -f /etc/ldap/slapd.conf -l /opt/crashtests-openldap/fixture.ldif && chown -R openldap:openldap /var/lib/ldap && exec slapd -f /etc/ldap/slapd.conf -h 'ldap:/// ldapi:///' -u openldap -g openldap -d 0"]
