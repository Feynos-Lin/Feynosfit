# Feynos Fit server (friends & step challenges)

A small, self-hosted server that lets Feynos Fit users add friends and compete in step
challenges. It's a single Go program with no third-party dependencies, packaged as a
~7 MB Docker image.

**What it stores:** username, display name, a hashed password, friend links, daily step
totals, and challenges. Food, weight and health data never leave the phone.

## 1. Start it

On your server (needs Docker with the compose plugin):

```sh
git clone https://github.com/Feynos-Lin/Feynosfit.git
cd Feynosfit/server
docker compose up -d --build
```

Get the **invite code** people need to create an account:

```sh
docker exec feynos-fit-server /feynos-server signup-code
```

The server now listens on `http://127.0.0.1:8095`, reachable only from the server itself.

## 2. Make it reachable over HTTPS

The app only connects over `https://`. Pick one:

- **Cloudflare Tunnel (recommended):** no router ports opened, and your home IP stays hidden.
  In Cloudflare Zero Trust → Networks → Tunnels, create a tunnel. Add a public hostname
  (e.g. `fit.example.com`) pointing to `http://feynos-fit:8095`. Paste the tunnel token
  into the `cloudflared` section of `docker-compose.yml`, uncomment it, and run
  `docker compose up -d`.
- **Your existing reverse proxy** (Caddy, Nginx, Nginx Proxy Manager, Traefik): proxy a
  hostname to `http://127.0.0.1:8095`. If the proxy itself runs in Docker, remove the
  `ports:` lines and put both containers on the same Docker network, then proxy to
  `http://feynos-fit-server:8095`.
- **Tailscale (most private):** `tailscale serve --bg --https=443 http://127.0.0.1:8095`,
  then use your `https://<machine>.<tailnet>.ts.net` address. Every friend must be on
  your tailnet.

Check it works: open `https://your-host/api/v1/health` in a browser. You should see
`{"ok":true,...}`.

## 3. Connect the app

In Feynos Fit, open the **Friends** tab, enter your server address and the invite code,
and create an account. Share the same address and invite code with your friends.
After that, add each other with the 8-character friend codes shown in the app.

## Web admin panel

Open `http://<your-server's-LAN-IP>:8097` from a phone or computer on your home network.

The first time, it asks for a one-time **setup code** and lets you create the admin password:

```sh
docker exec feynos-fit-server /feynos-server admin-setup-code
```

From the panel you can:

- see accounts, who synced recently, and friendships/challenge counts
- open or close sign-ups, and show, rotate or choose the invite code
- rename people, reset their password (the new one is shown once), sign them out of all
  devices, or delete them
- see and delete challenges and their leaderboards
- change the admin password and download a backup

How it's protected:

- It runs on its own port (8097) that never goes through your tunnel or reverse proxy, so
  it isn't reachable from the app's public address.
- It refuses any client that isn't on a private network (home LAN, Tailscale, or the
  machine itself), even if the port is accidentally forwarded. Proxy headers are ignored.
- It needs the admin password: 10+ characters, with a 15-minute lockout after 8 wrong tries.
  First-time setup needs the code from your server, so nobody else on your Wi-Fi can
  claim it first.
- Sessions use HttpOnly, SameSite=Strict cookies and expire after 12 hours. Every form has
  a CSRF token, and cross-site form posts are refused.
- There's no JavaScript, and the panel never loads anything from outside the server.

On a plain home network the panel uses `http://`, so only open it on networks you trust.
Over Tailscale the connection is encrypted anyway.

Forgot the admin password? `docker exec feynos-fit-server /feynos-server reset-admin-password`
prints a new setup code. Don't want the panel? Set `ADMIN_PANEL_ADDR: "off"` and remove the
`8097` port line.

## Admin commands

```sh
docker exec feynos-fit-server /feynos-server users                  # list accounts
docker exec feynos-fit-server /feynos-server reset-password <name>  # new random password
docker exec feynos-fit-server /feynos-server delete-user <name>     # remove account + data
docker exec feynos-fit-server /feynos-server new-signup-code        # rotate the invite code
```

Once everyone has joined, close sign-ups with the switch in the web admin panel (or set
`ALLOW_SIGNUP: "false"` in `docker-compose.yml` and run `docker compose up -d`). Once you've
used the panel's switch, it takes priority over `ALLOW_SIGNUP`.

## Update

```sh
cd Feynosfit && git pull && cd server && docker compose up -d --build
```

## Back up

Everything is in one file inside the `feynos-fit-data` volume:

```sh
docker cp feynos-fit-server:/data/feynos-fit.json ./feynos-fit-backup.json
```

## Security notes

- Passwords: PBKDF2-SHA256 with 600,000 iterations and a random salt per password.
- Sessions: random 256-bit tokens; only their SHA-256 hash is stored. They expire after
  180 days, and changing your password signs out your other devices.
- Rate limits: 30 sign-in/sign-up attempts per IP per 10 minutes; an account locks for
  15 minutes after 10 wrong passwords; friend-code lookups are throttled to stop guessing.
- Sign-ups need the invite code, and can be turned off entirely.
- Friends see only each other's step totals, and only after both sides accept. Challenge
  leaderboards show only members who chose to join.
- The container runs as a non-root user on a read-only filesystem with all Linux
  capabilities dropped. The command-line admin interface listens only inside the container.
- The web admin panel is home-network-only (see above). There's no third-party code to
  keep patched; keep Docker and your proxy/tunnel up to date.
