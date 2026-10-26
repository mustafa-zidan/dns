# Base images are pinned by digest; Dependabot keeps the digests current.
# The app builds once on the build machine's platform; the final stage only
# copies files, so multi-arch builds need no emulation.
FROM --platform=$BUILDPLATFORM node:26-alpine@sha256:40cd011b55415bc894e45b02fdd5a5dfde056921b7d23a64c74f80497af48797 AS build
WORKDIR /app
# Corepack fetches the pnpm release pinned, with its hash, in package.json.
# Node 25 and later no longer bundle Corepack, so it comes from npm.
ENV COREPACK_ENABLE_DOWNLOAD_PROMPT=0
RUN npm install --global --ignore-scripts corepack@0.36.0 && corepack enable
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
RUN pnpm install --frozen-lockfile
COPY . .
RUN pnpm build

FROM nginxinc/nginx-unprivileged:1.30-alpine@sha256:f5116ed4606f3eb015dd4a8e28cb9b351476dc0ad4bc6e9f93b19cec130cdf03
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
