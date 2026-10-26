# Base images are pinned by digest; Dependabot keeps the digests current.
# The app builds once on the build machine's platform; the final stage only
# copies files, so multi-arch builds need no emulation.
FROM --platform=$BUILDPLATFORM node:24-alpine@sha256:06d7adf3e0ef61a13f1d28682726366f97a15aa1888c934d3ecec86c33918b53 AS build
WORKDIR /app
# Corepack fetches the pnpm release pinned, with its hash, in package.json.
ENV COREPACK_ENABLE_DOWNLOAD_PROMPT=0
RUN corepack enable
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
RUN pnpm install --frozen-lockfile
COPY . .
RUN pnpm build

FROM nginxinc/nginx-unprivileged:1.31-alpine@sha256:b5047b9b76845eac124358373c6852377c52e4b05834a47647e955dd91cb8f1e
LABEL org.opencontainers.image.title="dns-dashboard" \
      org.opencontainers.image.description="Web dashboard for the dns ad-blocking DNS server" \
      org.opencontainers.image.source="https://github.com/mustafa-zidan/dns" \
      org.opencontainers.image.licenses="MIT OR Apache-2.0"
# The DNS server's API as the browser reaches it, such as http://localhost:8053.
# Leave empty to let each visitor enter a server address.
ENV DNS_API_URL=""
COPY --chmod=755 docker/05-dashboard.envsh /docker-entrypoint.d/
COPY docker/default.conf.template docker/security-headers.inc.template /etc/nginx/templates/
COPY --from=build /app/dist /usr/share/nginx/html
EXPOSE 8080
