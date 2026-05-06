# Tek konteyner: nginx+php+sshd+cron + ghostcatcher (tüm saldırı senaryoları aynı PID/mnt içinde)
FROM golang:1.22-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/ghostcatcher ./cmd/agent

FROM debian:bookworm-slim
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
		ca-certificates \
		nginx \
		php8.2-fpm \
		php8.2-cli \
		supervisor \
		cron \
		openssh-server \
		util-linux \
		netcat-openbsd \
		curl \
		libcap2-bin \
	&& rm -rf /var/lib/apt/lists/*

RUN install -d -m 0755 /var/lib/ghostcatcher /etc/ghostcatcher /opt/lab/skel /root/.ssh \
	&& chmod 700 /root/.ssh \
	&& touch /root/.ssh/authorized_keys && chmod 600 /root/.ssh/authorized_keys

RUN rm -f /etc/nginx/sites-enabled/default
COPY docker/lab/nginx-default.conf /etc/nginx/sites-enabled/default
COPY docker/lab/supervisord.conf /etc/supervisor/supervisord.conf
COPY docker/lab/entrypoint.sh /opt/lab/entrypoint.sh
COPY docker/lab/reset.sh /opt/lab/reset.sh
COPY docker/lab/attackctl /opt/lab/attackctl
COPY docker/lab/sshd-99-lab.conf /etc/ssh/sshd_config.d/99-lab.conf
RUN chmod +x /opt/lab/entrypoint.sh /opt/lab/reset.sh /opt/lab/attackctl \
	&& ln -sf /opt/lab/attackctl /usr/local/bin/attackctl

COPY docker/lab/www/ /var/www/html/
COPY docker/lab/skel/ /opt/lab/skel/
COPY docker/lab/scenarios/ /opt/lab/scenarios/
RUN chmod +x /opt/lab/scenarios/*.sh

COPY --from=build /out/ghostcatcher /usr/local/bin/ghostcatcher
COPY docker/lab/lab.config.yaml /etc/ghostcatcher/lab.config.yaml

# Temiz web kökü yedeği
RUN tar -czf /opt/lab/golden.tgz -C / var/www/html

EXPOSE 80 22
ENTRYPOINT ["/opt/lab/entrypoint.sh"]
