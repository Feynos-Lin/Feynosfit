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

## Admin commands

```sh
docker exec feynos-fit-server /feynos-server users                  # list accounts
docker exec feynos-fit-server /feynos-server reset-password <name>  # new random password
docker exec feynos-fit-server /feynos-server delete-user <name>     # remove account + data
docker exec feynos-fit-server /feynos-server new-signup-code        # rotate the invite code
```

Once everyone has joined, set `ALLOW_SIGNUP: "false"` in `docker-compose.yml` and run
`docker compose up -d` to close sign-ups.

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
  capabilities dropped. The admin interface listens only inside the container.
- There's no web admin panel and no third-party code to keep patched. Keep Docker and
  your proxy/tunnel up to date.
