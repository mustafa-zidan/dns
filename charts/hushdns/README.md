# hushdns Helm chart

Runs the [hushdns](https://github.com/mustafa-zidan/hushdns) ad-blocking DNS server and its web dashboard on Kubernetes. Everything is set through values, including the server's own config, so there's no config file to manage by hand.

```sh
helm install hushdns oci://ghcr.io/mustafa-zidan/charts/hushdns -f my-values.yaml
```

## What it creates

- A Deployment and Service for the server. The Service serves DNS on port 53 (UDP and TCP), plus DNS-over-TLS on 853 and DNS-over-HTTPS on 443 when TLS is on.
- A Secret holding the rendered `hushdns.toml` and the API token.
- A ClusterIP Service for the API, with an optional Ingress.
- A Deployment, Service and optional Ingress for the dashboard.
- A cert-manager Certificate, when you ask for one.

Both containers run as non-root with a read-only root filesystem and no capabilities. The server binds port 53 through the `net.ipv4.ip_unprivileged_port_start` sysctl, which Kubernetes allows by default.

## Serving your network

The Service is `ClusterIP` by default, so only pods can reach it. To serve devices on your LAN, use a `LoadBalancer`, for example with MetalLB:

```yaml
service:
  type: LoadBalancer
  loadBalancerIP: 192.168.1.53
```

`externalTrafficPolicy` defaults to `Local`, so the server sees each device's real address. Per-client rules need that.

## Server config

`config` takes the same keys as [`config/hushdns.toml`](../../config/hushdns.toml), written as YAML. The chart fills in the listeners, the API token and the certificate paths, so leave those out.

```yaml
config:
  server:
    timezone: Europe/Berlin
  blocking:
    lists:
      - https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts
    denylist: [ads.example.com]
  clients:
    - name: kids
      addresses: ["192.168.1.20", "192.168.1.64/28"]
      denylist: [youtube.com]
      schedules:
        - days: [sun, mon, tue, wed, thu]
          from: "21:00"
          to: "07:00"
          block_all: true
```

To manage the whole file yourself, put it in a Secret under the `hushdns.toml` key and set `existingConfigSecret`.

## API token and dashboard

The API always needs a token in the cluster. Set `api.token`, or let the chart generate one, which it keeps across upgrades. Read it with:

```sh
kubectl get secret hushdns -o jsonpath='{.data.api-token}' | base64 -d; echo
```

The dashboard runs in your browser and calls the API directly, so the browser has to reach both. With no ingress, port-forward both and open <http://localhost:8080>:

```sh
kubectl port-forward service/hushdns-dashboard 8080:8080 &
kubectl port-forward service/hushdns-api 8053:8053 &
```

With ingress, give each one a host. The chart points the dashboard at the API's host and adds the dashboard's host to the API's allowed origins:

```yaml
api:
  ingress:
    enabled: true
    hosts: [api.dns.example.com]
    tls: [{secretName: dns-api-tls, hosts: [api.dns.example.com]}]
dashboard:
  ingress:
    enabled: true
    hosts: [dns.example.com]
    tls: [{secretName: hushdns-dashboard-tls, hosts: [dns.example.com]}]
```

## DNS-over-TLS and DNS-over-HTTPS

Turn on `tls` and give it a certificate, either as a `kubernetes.io/tls` Secret or from cert-manager:

```yaml
tls:
  enabled: true
  certManager:
    enabled: true
    issuerRef: {name: letsencrypt, kind: ClusterIssuer}
    dnsNames: [dns.example.com]
```

The certificate is mounted as a directory, so a renewal reaches the running pod and the server picks it up without a restart. Set `tls.dot` or `tls.doh` to `false` to serve only one of them.

## Logs

Logs are JSON by default (`env.HUSHDNS_LOG_FORMAT`). Add `HUSHDNS_LOG: "info,hushdns::query=debug"` under `env` for one log line per query. The repository README lists the fields.

## Values

See [`values.yaml`](values.yaml). Every value has a comment there.
