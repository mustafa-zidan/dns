# Point your devices at it

hushdns only filters the queries it receives. You can send it your whole network's queries through your router, or set it up one device at a time.

Give the machine running hushdns a fixed address first, for example a DHCP reservation for `192.168.1.53`. The examples below use that address.

## The whole network, through your router

In your router's DHCP or LAN settings, set the DNS server handed to clients to the hushdns address. Leave the secondary DNS empty, or set it to a second hushdns instance. If the secondary is a public resolver, devices will use it some of the time and get around the blocking.

Devices pick up the new server when they renew their DHCP lease. Reconnecting to the network, or rebooting, does it right away.

Some routers can only forward to an upstream resolver and always give clients the router's own address. Then every query looks as if it came from the router, and [per-client rules](clients.md) can't tell devices apart. If you can, turn off the router's DNS forwarding, or set the DNS server in its DHCP settings instead.

## One device, plain DNS

Set the DNS server in the device's network settings to `192.168.1.53`:

- **Windows:** Settings → Network & internet → your connection → DNS server assignment → Edit.
- **macOS:** System Settings → Network → your connection → Details → DNS.
- **Linux with systemd-resolved:** `resolvectl dns <interface> 192.168.1.53`, or `DNS=` in `/etc/systemd/resolved.conf`.
- **iOS and Android:** in the Wi-Fi network's settings, switch DNS to manual.

## Encrypted DNS on phones and laptops

With [DNS-over-TLS or DNS-over-HTTPS turned on](encrypted-dns.md#serving-your-devices), devices can reach hushdns encrypted, even away from home if you expose it. The certificate must be valid for the name the device connects to, here `dns.example.com`.

- **Android 9 and later:** Settings → Network & internet → Private DNS → enter `dns.example.com`. This uses DNS-over-TLS on port 853.
- **Chrome, Edge, Firefox:** turn on secure DNS and pick a custom provider of `https://dns.example.com/dns-query`.
- **Windows 11:** set the DNS server to the hushdns address, then set DNS-over-HTTPS to on, with the template `https://dns.example.com/dns-query`.
- **iOS and macOS:** install a configuration profile with a `DNSSettings` payload, `DNSProtocol` set to `HTTPS` and `ServerURL` set to `https://dns.example.com/dns-query`.

## Checking that it works

Look up a name you've blocked, and one you haven't:

```sh
dig @192.168.1.53 ads.example.com   # status: NXDOMAIN when blocked
dig @192.168.1.53 example.com       # a normal answer
```

The [dashboard](dashboard.md) shows the queries arriving. Its domain checker tells you whether a name is blocked, and by which rule.
