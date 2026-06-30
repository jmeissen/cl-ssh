FROM debian:bookworm-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends openssh-server openssh-client ca-certificates \
 && rm -rf /var/lib/apt/lists/*

RUN useradd --badname -m -s /bin/sh 'ssh-tést' \
 && install -d -m 700 -o 'ssh-tést' -g 'ssh-tést' '/home/ssh-tést/.ssh'

COPY tests/fixtures/keys/*.pub /tmp/ssh-keys/
RUN cat /tmp/ssh-keys/*.pub > '/home/ssh-tést/.ssh/authorized_keys' \
 && chown 'ssh-tést:ssh-tést' '/home/ssh-tést/.ssh/authorized_keys' \
 && chmod 600 '/home/ssh-tést/.ssh/authorized_keys' \
 && printf '%s:%s\n' 'ssh-tést' 'cl-ssh-pässwörd-値' | chpasswd \
 && rm -rf /tmp/ssh-keys

COPY docker/sshd_config /etc/ssh/sshd_config
COPY docker/entrypoint.sh /usr/local/bin/ssh-entrypoint
RUN chmod 755 /usr/local/bin/ssh-entrypoint \
 && ssh-keygen -A

EXPOSE 22

ENTRYPOINT ["/usr/local/bin/ssh-entrypoint"]
