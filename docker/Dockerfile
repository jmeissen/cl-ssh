FROM debian:bookworm-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends openssh-server openssh-client ca-certificates \
 && rm -rf /var/lib/apt/lists/*

RUN useradd -m -s /bin/sh ssh-test \
 && install -d -m 700 -o ssh-test -g ssh-test /home/ssh-test/.ssh

COPY tests/fixtures/keys/*.pub /tmp/ssh-keys/
RUN cat /tmp/ssh-keys/*.pub > /home/ssh-test/.ssh/authorized_keys \
 && chown ssh-test:ssh-test /home/ssh-test/.ssh/authorized_keys \
 && chmod 600 /home/ssh-test/.ssh/authorized_keys \
 && echo 'ssh-test:cl-ssh-password' | chpasswd \
 && rm -rf /tmp/ssh-keys

COPY docker/sshd_config /etc/ssh/sshd_config
COPY docker/entrypoint.sh /usr/local/bin/ssh-entrypoint
RUN chmod 755 /usr/local/bin/ssh-entrypoint \
 && ssh-keygen -A

EXPOSE 22

ENTRYPOINT ["/usr/local/bin/ssh-entrypoint"]
