# Running Gono Cloud behind a reverse proxy

Gono Cloud serves plain HTTP on a loopback address and expects a reverse proxy in front of it
to terminate HTTPS. This guide shows working configurations for **nginx** and **Caddy** and
explains which Gono Cloud settings have to match the proxy. It covers only the proxy; installing
the server as a service, upgrades and backups are in [deployment.md](deployment.md).

## What the proxy has to do

| Requirement | Why |
|---|---|
| Terminate TLS and forward everything to `server.bind` | Gono Cloud has no TLS of its own. |
| Pass the request path through **unchanged** | WebDAV paths carry percent-encoded file names; a proxy that decodes or re-encodes them (nginx with a URI in `proxy_pass`) renames files or breaks requests. |
| Pass every HTTP method and header | WebDAV uses `PROPFIND`, `PROPPATCH`, `MKCOL`, `COPY`, `MOVE`, `LOCK`, `UNLOCK`, `REPORT`, and headers such as `Depth`, `Destination`, `Overwrite`, `If`, `OC-Total-Length`. |
| Upgrade WebSockets on `/push/ws` | notify_push (real-time change notifications) runs over a WebSocket. |
| Stream request and response bodies | Uploads and downloads can be gigabytes; buffering them in the proxy costs disk space and time and breaks progress reporting. |
| Allow large request bodies | Nextcloud clients upload big files in chunks, but generic WebDAV clients (Finder, rclone, Cyberduck, the mobile apps for some uploads) send a whole file in one `PUT`. |
| Keep long requests and idle WebSockets open | A WebSocket is quiet between pings (`notify_push.ping_interval_secs`, 30 s by default); large transfers can take hours. |
| Send the client address in `X-Forwarded-For` (or `Forwarded`) | Failed-login rate limiting and the logs work per client address. |

## Gono Cloud settings that must match

```toml
[server]
# Gono Cloud listens on loopback; only the proxy connects to it.
bind = "127.0.0.1:16102"

# The public origin, exactly as users and clients type it: scheme, host and port (if not the
# default), no path. Serving under a sub-path such as https://example.com/cloud is not
# supported.
base_url = "https://cloud.example.com"

# Proxies whose X-Forwarded-For / Forwarded headers are believed.
trusted_proxies = ["127.0.0.1", "::1"]
```

- **`base_url` is never guessed from the request.** Gono Cloud ignores `Host`,
  `X-Forwarded-Host` and `X-Forwarded-Proto`. Everything that needs the public origin uses
  `base_url`:
  - absolute URLs handed to clients: Login Flow v2 links, and the notify_push endpoints in the
    capabilities (`wss://cloud.example.com/push/ws` when `base_url` is `https://...`);
  - the `Secure` flag of browser cookies (set when `base_url` is `https`);
  - the origin check of every HTML form (Login Flow and the web admin UI): a browser that
    sends `Origin: https://cloud.example.com` is accepted only if that is `base_url`'s origin.

  If `base_url` does not match the address users open, signing in through the browser fails
  with "Request blocked" and push clients connect to the wrong place. `gono-cloud config check`
  warns when `base_url` is plain `http` on a public host.
- **`trusted_proxies` decides whose forwarding headers count.** A request from any other peer is
  attributed to the peer address, and its `X-Forwarded-For` is ignored, so clients cannot pick an
  address to escape the rate limiter. With a trusted peer, the chain is walked from the right
  (the hop closest to Gono Cloud), skipping trusted proxies; the first other address is the
  client. List every proxy hop that talks to Gono Cloud or appends to the header:
  - proxy on the same host: `["127.0.0.1", "::1"]`;
  - proxy in another container: the container network, for example `["172.18.0.0/16"]`, and
    `bind` on that network with `allow_non_loopback_bind = true`;
  - a CDN or load balancer in front of nginx: nginx's address **and** the CDN's address ranges,
    or let nginx replace the header (see below).
- **notify_push timing:** the proxy's idle timeout for the WebSocket must be longer than
  `notify_push.ping_interval_secs`. Gono Cloud pings every interval and closes connections that
  do not answer by the next ping, so an idle timeout of at least twice the interval is safe.
- **Admin UI:** `admin.enabled` and `admin.path` (default `/gono-admin`). The proxy may restrict
  that path further, for example to a VPN range (examples below).

## nginx

Needs nginx 1.25.1 or later for `http2 on;` (with older versions, write
`listen 443 ssl http2;` instead). Replace the server name, certificate paths and the upstream
address. The whole acceptance suite, notify_push included, passes through this configuration
(checked with nginx 1.31, with TLS replaced by a plain local port; `acceptance/README.md` shows
how to run the suite through a proxy).

```nginx
# WebSocket upgrades: pass "Connection: upgrade" only when the client asked for one.
map $http_upgrade $connection_upgrade {
    default upgrade;
    ''      close;
}

upstream gono_cloud {
    server 127.0.0.1:16102;
    keepalive 16;
}

server {
    listen 80;
    listen [::]:80;
    server_name cloud.example.com;
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl;
    listen [::]:443 ssl;
    http2 on;
    server_name cloud.example.com;

    ssl_certificate     /etc/letsencrypt/live/cloud.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/cloud.example.com/privkey.pem;

    # Browsers must only use HTTPS from now on (Gono Cloud sets the other page headers itself).
    add_header Strict-Transport-Security "max-age=31536000" always;

    # Uploads: no size limit, and streamed to Gono Cloud instead of buffered to disk first.
    client_max_body_size 0;
    proxy_request_buffering off;

    # Downloads: streamed to the client as they arrive.
    proxy_buffering off;
    proxy_max_temp_file_size 0;

    # Large transfers and idle WebSockets.
    proxy_read_timeout 1h;
    proxy_send_timeout 1h;
    send_timeout 1h;

    location / {
        # No URI after the address: the original request path is passed unchanged.
        proxy_pass http://gono_cloud;
        proxy_http_version 1.1;
        proxy_set_header Connection "";

        proxy_set_header Host $host;
        # nginx is the first proxy: replace whatever the client sent.
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    # notify_push WebSocket.
    location = /push/ws {
        proxy_pass http://gono_cloud;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection $connection_upgrade;

        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    # Optional: the admin UI only from the office network or a VPN.
    # location /gono-admin {
    #     allow 10.8.0.0/24;
    #     deny all;
    #     proxy_pass http://gono_cloud;
    #     proxy_http_version 1.1;
    #     proxy_set_header Connection "";
    #     proxy_set_header Host $host;
    #     proxy_set_header X-Forwarded-For $remote_addr;
    #     proxy_set_header X-Forwarded-Proto $scheme;
    # }
}
```

Notes:

- **`proxy_pass` without a URI.** `proxy_pass http://gono_cloud;` forwards the request path as
  the client sent it. Writing `proxy_pass http://gono_cloud/;` (with a trailing slash or any
  other URI) makes nginx decode and re-encode the path, which corrupts file names with `%2F`,
  `%25` and similar sequences.
- **`X-Forwarded-For`.** `$remote_addr` replaces the header, which is right when nginx is the
  edge. When another proxy or a CDN sits in front of nginx, use
  `$proxy_add_x_forwarded_for` instead (it appends) and list that proxy in `trusted_proxies`
  too; otherwise every request appears to come from it, and one client's failed logins slow
  everybody down.
- **`client_max_body_size 0`** disables the limit. To keep one, set it to at least the largest
  file anyone uploads in a single `PUT`.
- **HTTP/2** to the clients is fine; nginx speaks HTTP/1.1 to Gono Cloud. WebSockets over the
  HTTP/2 connection fall back to HTTP/1.1 automatically in today's clients.
- nginx does not need to rewrite `Destination` headers (`COPY`, `MOVE`): Gono Cloud only uses
  their path.

## Caddy

For Caddy 2. Caddy obtains and renews the certificate itself. The whole acceptance suite,
notify_push included, and litmus pass through this configuration (checked with Caddy 2.11.9,
with TLS replaced by a plain local port).

```caddyfile
cloud.example.com {
	# Browsers must only use HTTPS from now on (Gono Cloud sets the other page headers itself).
	header Strict-Transport-Security "max-age=31536000"

	# Optional: the admin UI only from the office network or a VPN.
	# @admin_outside {
	# 	path /gono-admin /gono-admin/*
	# 	not remote_ip 10.8.0.0/24
	# }
	# respond @admin_outside 403

	reverse_proxy 127.0.0.1:16102 {
		# Stream responses (downloads) as they arrive.
		flush_interval -1
	}
}
```

Caddy already does the rest by default:

- WebSocket upgrades are proxied for every path, including `/push/ws`, and idle WebSockets are
  not timed out.
- Request bodies are streamed, not buffered, and there is no size limit unless a
  `request_body { max_size ... }` directive sets one.
- The request path is forwarded unchanged.
- `X-Forwarded-For` is set to the client address. Caddy ignores the header the client sent
  unless the client is listed in Caddy's own `trusted_proxies` server option; add that option
  only when a CDN or load balancer sits in front of Caddy, and then list that hop in Gono
  Cloud's `trusted_proxies` as well.

If Caddy runs in a container and reaches Gono Cloud over a container network, point
`reverse_proxy` at Gono Cloud's container address, set `bind` to that interface with
`allow_non_loopback_bind = true`, and put the container network in `trusted_proxies`.

## Checking the setup

```sh
# The server answers through the proxy and reports itself.
curl -s https://cloud.example.com/status.php

# The capabilities advertise the public WebSocket URL (wss:// for an https base_url).
curl -s 'https://cloud.example.com/ocs/v2.php/cloud/capabilities?format=json' \
  | python3 -m json.tool | grep -A3 '"endpoints"'

# The WebSocket upgrade reaches Gono Cloud: expect "HTTP/1.1 101 Switching Protocols".
curl -si --http1.1 -o /dev/null -w '%{http_code}\n' \
  -H 'Connection: Upgrade' -H 'Upgrade: websocket' \
  -H 'Sec-WebSocket-Version: 13' -H 'Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==' \
  --max-time 3 https://cloud.example.com/push/ws
```

Then sign in to the admin UI at `https://cloud.example.com/gono-admin/` (when
`admin.enabled`): its overview shows the configured public URL, the trusted proxies and the
number of live push connections. A "Request blocked" page after submitting a form means the
browser's origin does not match `base_url`.
