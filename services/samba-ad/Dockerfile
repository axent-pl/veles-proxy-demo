FROM instantlinux/samba-dc:latest
RUN apk add --no-cache bash
COPY wrapper-entrypoint.sh /usr/local/bin/wrapper-entrypoint.sh
COPY scripts /opt/scripts
COPY etc/samba/conf.d /etc/samba/conf.d
ENTRYPOINT ["/usr/local/bin/wrapper-entrypoint.sh"]