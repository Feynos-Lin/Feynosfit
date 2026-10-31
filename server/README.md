# Feynos Fit server (friends & step challenges)

A small, self-hosted server that lets Feynos Fit users add friends and compete in step
challenges. It's a single Go program with no third-party dependencies, packaged as a
~7 MB Docker image.

**What it stores:** username, display name, a hashed password, friend links, daily step
totals, and challenges. Food, weight and health data never leave the phone.

## 1. Start it

The server is published as a ready-made Docker image, `ghcr.io/feynos-lin/feynosfit-server`
(for normal PCs and ARM boards like a Raspberry Pi). You only need a compose file, not the
source code.

### Already have a main compose.yaml that includes each app?

Make a `Feynosfit` folder next to your other app folders and save the repo's root
[`compose.yaml`](../compose.yaml) in it. Add one line to your main `compose.yaml`:

```yaml
include:
  - Feynosfit/compose.yaml
```

Then, from the folder with your main file:

```powershell
docker compose up -d
docker exec feynos-fit-server /feynos-server signup-code
docker exec feynos-fit-server /feynos-server admin-setup-code
```

It keeps its data in a Docker volume named `feynos-fit-data`. If nginx runs in the same
compose setup, proxy your hostname to `http://feynos-fit:8095`.

### On its own

Save [`docker-compose.yml`](docker-compose.yml) in an empty folder and run `docker compose up -d`
there, then get the invite code:

```sh
docker exec feynos-fit-server /feynos-server signup-code
```

That file publishes the API on `127.0.0.1:8095`, so only the server itself can reach it.
Opening `http://<server>:8095/` in a browser shows "Feynos Fit server … is running".

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
(On Windows, `ipconfig` shows the IP as "IPv4 Address". If your phone can't reach it, allow
port 8097 for private networks in Windows Defender Firewall.)

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
- set up fast-food search (FatSecret keys)
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

## Fast-food search (FatSecret)

Open Food Facts, which the app uses for packaged foods, has very few restaurant items. Your
server can add restaurant chains and brands from FatSecret. The server makes the requests, so
the secret key never goes into the app, and everyone signed in to your server gets it.

1. Sign up at [platform.fatsecret.com](https://platform.fatsecret.com) (the free Basic plan is
   enough) and create an app. Copy its **OAuth 2.0 Client ID** and **Client Secret**.
2. In your FatSecret account, open **IP Restrictions** and add your home internet's public IP
   address (search "what is my IP" from a device at home). FatSecret refuses every other address.
   Changes can take a while to apply.
3. In the web admin panel, open **Settings → Fast-food search**, paste both keys, press
   **Save**, then **Test**. If it fails because of the IP address, the message shows the
   address FatSecret saw.

In the app, food search then shows a **Restaurants & brands** section above the packaged foods.
Results are cached on the server for 24 hours, and each person is limited to 120 searches
per 10 minutes so the free plan's daily limit isn't used up.

If your home IP changes (most home internet does now and then), search will stop working until
you add the new address in FatSecret. The admin panel shows the error.

You can also set the keys with `FATSECRET_CLIENT_ID` and `FATSECRET_CLIENT_SECRET` in the compose
file. They take priority over the panel.

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

From the folder with your compose file (your main one, if you use `include:`):

```sh
docker compose pull feynos-fit
docker compose up -d
```

Your data lives in the Docker volume, so updating never touches it. New images are published
automatically whenever the server code changes.

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
