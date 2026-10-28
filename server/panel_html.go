package main

const panelHTML = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<title>Feynos Fit · Admin</title>
<style>
:root {
  --bg: #f4f7f2; --card: #ffffff; --text: #18201a; --dim: #5d6b60; --line: #dfe7dc;
  --accent: #1e8e3e; --accent-ink: #ffffff; --tint: #e3f4e6; --bad: #c62828; --bad-tint: #fdecea;
  --warn-tint: #fff4dc; --mono: ui-monospace, "SF Mono", Menlo, Consolas, monospace;
}
@media (prefers-color-scheme: dark) {
  :root {
    --bg: #0f1310; --card: #171d18; --text: #e3e8e2; --dim: #9aa79c; --line: #283129;
    --accent: #6fdb8f; --accent-ink: #062b12; --tint: #183a22; --bad: #ff8a80; --bad-tint: #3a1d1b;
    --warn-tint: #3a3018;
  }
}
* { box-sizing: border-box; }
body { margin: 0; background: var(--bg); color: var(--text);
  font: 15px/1.5 system-ui, -apple-system, "Segoe UI", Roboto, sans-serif; }
a { color: var(--accent); }
header { background: var(--card); border-bottom: 1px solid var(--line); }
.bar { max-width: 960px; margin: 0 auto; padding: 12px 16px; display: flex; align-items: center; gap: 16px; flex-wrap: wrap; }
.brand { font-weight: 700; display: flex; align-items: center; gap: 8px; }
.logo { width: 26px; height: 26px; border-radius: 7px; background: var(--accent); color: var(--accent-ink);
  display: grid; place-items: center; font-weight: 800; font-size: 15px; }
nav { display: flex; gap: 4px; flex: 1; }
.bar > form { margin-left: auto; }
nav a { text-decoration: none; color: var(--dim); padding: 6px 10px; border-radius: 8px; font-weight: 500; }
nav a.on { background: var(--tint); color: var(--text); }
main { max-width: 960px; margin: 0 auto; padding: 20px 16px 48px; }
h1 { font-size: 22px; margin: 0 0 16px; }
h2 { font-size: 16px; margin: 0 0 10px; }
.card { background: var(--card); border: 1px solid var(--line); border-radius: 14px; padding: 16px; margin-bottom: 14px; }
.stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 12px; margin-bottom: 14px; }
.stat { background: var(--card); border: 1px solid var(--line); border-radius: 14px; padding: 14px 16px; }
.stat b { display: block; font-size: 26px; line-height: 1.1; }
.stat span { color: var(--dim); font-size: 13px; }
.dim { color: var(--dim); }
.small { font-size: 13px; }
.row { display: flex; gap: 10px; align-items: center; flex-wrap: wrap; }
.spread { justify-content: space-between; }
.code { font-family: var(--mono); font-size: 24px; letter-spacing: 2px; font-weight: 700; background: var(--tint);
  padding: 6px 12px; border-radius: 10px; user-select: all; }
.pill { display: inline-block; padding: 2px 9px; border-radius: 99px; font-size: 12px; font-weight: 600; background: var(--tint); }
.pill.off { background: var(--bad-tint); color: var(--bad); }
.pill.grey { background: var(--line); color: var(--dim); }
button, .btn { font: inherit; font-weight: 600; border: 0; border-radius: 10px; padding: 8px 14px; cursor: pointer;
  background: var(--accent); color: var(--accent-ink); text-decoration: none; display: inline-block; }
button.ghost, .btn.ghost { background: transparent; color: var(--accent); border: 1px solid var(--line); }
button.danger { background: var(--bad); color: #fff; }
input[type=text], input[type=password] { font: inherit; color: var(--text); background: var(--bg); border: 1px solid var(--line);
  border-radius: 10px; padding: 8px 10px; min-width: 0; }
input:focus-visible, button:focus-visible, a:focus-visible, summary:focus-visible { outline: 2px solid var(--accent); outline-offset: 2px; }
form.inline { display: inline; }
label.check { display: flex; gap: 6px; align-items: center; font-size: 13px; }
.flash { padding: 10px 14px; border-radius: 10px; background: var(--tint); margin-bottom: 14px; }
.flash.bad { background: var(--bad-tint); color: var(--bad); }
.secret { background: var(--warn-tint); }
table { width: 100%; border-collapse: collapse; }
th { white-space: nowrap; text-align: left; font-size: 12px; text-transform: uppercase; letter-spacing: .04em; color: var(--dim); font-weight: 600; padding: 6px 8px; }
td { padding: 10px 8px; border-top: 1px solid var(--line); vertical-align: top; }
td.num, th.num { text-align: right; font-variant-numeric: tabular-nums; }
details > summary { cursor: pointer; color: var(--accent); font-weight: 600; font-size: 13px; list-style: none; }
details > summary::-webkit-details-marker { display: none; }
details[open] > summary { margin-bottom: 8px; }
.actions { display: flex; flex-wrap: wrap; gap: 8px; align-items: center; padding: 10px; background: var(--bg); border-radius: 10px; }
.actions .row { flex-basis: 100%; }
.auth { max-width: 420px; margin: 8vh auto; }
.auth .card { padding: 22px; }
.auth form { display: grid; gap: 10px; }
.cmd { font-family: var(--mono); font-size: 12.5px; background: var(--bg); border: 1px solid var(--line); padding: 8px 10px; border-radius: 8px; overflow-x: auto; white-space: nowrap; }
.board { margin: 6px 0 0; padding-left: 20px; }
.person { display: grid; grid-template-columns: minmax(160px, 1.2fr) 2fr; gap: 8px 16px; align-items: center; }
.person .who { display: grid; }
.person .nums { display: grid; grid-template-columns: repeat(4, 1fr); gap: 8px; text-align: right; }
.person .nums b { display: block; font-variant-numeric: tabular-nums; }
.person .nums span { font-size: 12px; color: var(--dim); }
.person details { grid-column: 1 / -1; }
.person input[type=text] { flex: 1; }
@media (max-width: 640px) {
  .bar { gap: 8px 12px; padding-bottom: 8px; }
  nav { order: 3; flex-basis: 100%; overflow-x: auto; flex-wrap: nowrap; margin: 0 -6px; }
  nav a { white-space: nowrap; }
  .hide-sm { display: none; }
  .person { grid-template-columns: 1fr; }
  .person .nums { grid-template-columns: repeat(2, 1fr); text-align: left; }
  td, th { padding: 8px 4px; }
}
</style>
</head>
<body>
{{if or (eq .Page "setup") (eq .Page "login")}}
<div class="auth">
  <div class="brand" style="justify-content:center;margin-bottom:16px"><span class="logo">F</span> Feynos Fit server</div>
  <div class="card">
  {{if .Flash}}<div class="flash{{if .FlashBad}} bad{{end}}">{{.Flash}}</div>{{end}}
  {{if eq .Page "setup"}}
    <h1>Set up the admin panel</h1>
    <p class="dim small">Create the admin password. To prove you own this server, enter the one-time setup code. See it by running this on the server:</p>
    <div class="cmd">docker exec feynos-fit-server /feynos-server admin-setup-code</div>
    <form method="post" action="/setup" autocomplete="off">
      <input type="text" name="code" placeholder="Setup code" required autocapitalize="characters" spellcheck="false">
      <input type="password" name="password" placeholder="New admin password (10+ characters)" minlength="10" required autocomplete="new-password">
      <input type="password" name="password2" placeholder="Repeat password" minlength="10" required autocomplete="new-password">
      <button>Create admin password</button>
    </form>
  {{else}}
    <h1>Admin sign-in</h1>
    <form method="post" action="/login">
      <input type="password" name="password" placeholder="Admin password" required autofocus autocomplete="current-password">
      <button>Sign in</button>
    </form>
    <p class="dim small">Forgot it? Run <span class="cmd" style="display:inline-block;padding:2px 6px">docker exec feynos-fit-server /feynos-server reset-admin-password</span> and set it up again.</p>
  {{end}}
  </div>
</div>
{{else}}
<header><div class="bar">
  <div class="brand"><span class="logo">F</span> Feynos Fit</div>
  <nav>
    <a href="/" {{if eq .Page "home"}}class="on"{{end}}>Overview</a>
    <a href="/users" {{if eq .Page "users"}}class="on"{{end}}>People</a>
    <a href="/challenges" {{if eq .Page "challenges"}}class="on"{{end}}>Challenges</a>
    <a href="/settings" {{if eq .Page "settings"}}class="on"{{end}}>Settings</a>
  </nav>
  <form class="inline" method="post" action="/logout"><input type="hidden" name="csrf" value="{{.CSRF}}"><button class="ghost">Sign out</button></form>
</div></header>
<main>
{{if .Flash}}<div class="flash{{if .FlashBad}} bad{{end}}">{{.Flash}}</div>{{end}}

{{if eq .Page "home"}}
  <h1>Overview</h1>
  <div class="stats">
    <div class="stat"><b>{{len .Users}}</b><span>accounts</span></div>
    <div class="stat"><b>{{.ActiveToday}}</b><span>synced in last 24 h</span></div>
    <div class="stat"><b>{{.Friendships}}</b><span>friendships</span></div>
    <div class="stat"><b>{{.ActiveCh}}</b><span>active challenges</span></div>
  </div>
  <div class="card">
    <div class="row spread">
      <h2 style="margin:0">New accounts</h2>
      {{if .SignupOpen}}<span class="pill">Sign-ups open</span>{{else}}<span class="pill off">Sign-ups closed</span>{{end}}
    </div>
    <p class="dim small">People need the server address and this invite code to create an account in the app.</p>
    <div class="row" style="margin-bottom:12px"><span class="code">{{.InviteCode}}</span></div>
    <div class="row">
      <form class="inline" method="post" action="/signups"><input type="hidden" name="csrf" value="{{.CSRF}}">
        {{if .SignupOpen}}<input type="hidden" name="open" value="0"><button class="ghost">Close sign-ups</button>
        {{else}}<input type="hidden" name="open" value="1"><button>Open sign-ups</button>{{end}}
      </form>
      <form class="inline" method="post" action="/invite/new"><input type="hidden" name="csrf" value="{{.CSRF}}"><button class="ghost">New random code</button></form>
    </div>
    <details style="margin-top:12px"><summary>Choose my own code</summary>
      <form class="row" method="post" action="/invite/set"><input type="hidden" name="csrf" value="{{.CSRF}}">
        <input type="text" name="code" placeholder="6–32 letters or numbers" pattern="[A-Za-z0-9]{6,32}" required autocapitalize="characters">
        <button>Save</button>
      </form>
    </details>
  </div>
  <div class="card">
    <div class="row spread"><h2 style="margin:0">Newest accounts</h2><a class="small" href="/users">All people →</a></div>
    {{if .Users}}
    <table><tr><th>Name</th><th class="hide-sm">Joined</th><th class="num">Today</th><th class="num hide-sm">Last sync</th></tr>
    {{range $i, $u := .Users}}{{if lt $i 5}}
      <tr><td><b>{{$u.DisplayName}}</b><br><span class="dim small">@{{$u.Username}}</span></td>
      <td class="hide-sm">{{date $u.Created}}</td><td class="num">{{num $u.Today}}</td><td class="num hide-sm">{{ago $u.LastSync}}</td></tr>
    {{end}}{{end}}
    </table>
    {{else}}<p class="dim">No accounts yet. Share your server address and the invite code above.</p>{{end}}
  </div>

{{else if eq .Page "users"}}
  <h1>People</h1>
  {{if .Secret}}
  <div class="flash secret">New password for <b>@{{.SecretFor}}</b>: <span class="code" style="font-size:18px">{{.Secret}}</span><br>
  <span class="small">Shown only once. They've been signed out everywhere; give them this password to sign back in.</span></div>
  {{end}}
  {{if .Users}}
  {{range .Users}}
  <div class="card person">
    <div class="who"><b>{{.DisplayName}}</b><span class="dim small">@{{.Username}} · joined {{date .Created}}{{if .Pending}} · {{.Pending}} pending request{{if ne .Pending 1}}s{{end}}{{end}}</span></div>
    <div class="nums">
      <div><b>{{num .Today}}</b><span>today</span></div>
      <div><b>{{num .Week}}</b><span>7 days</span></div>
      <div><b>{{.Friends}}</b><span>friends</span></div>
      <div><b>{{ago .LastSync}}</b><span>{{.Devices}} device{{if ne .Devices 1}}s{{end}}</span></div>
    </div>
    <details><summary>Manage</summary>
    <div class="actions">
      <form class="row" method="post" action="/users/rename"><input type="hidden" name="csrf" value="{{$.CSRF}}"><input type="hidden" name="id" value="{{.ID}}">
        <input type="text" name="name" value="{{.DisplayName}}" maxlength="40" required aria-label="Display name"><button class="ghost">Rename</button></form>
      <form method="post" action="/users/reset"><input type="hidden" name="csrf" value="{{$.CSRF}}"><input type="hidden" name="id" value="{{.ID}}">
        <button class="ghost">Reset password</button></form>
      <form method="post" action="/users/signout"><input type="hidden" name="csrf" value="{{$.CSRF}}"><input type="hidden" name="id" value="{{.ID}}">
        <button class="ghost">Sign out of all devices</button></form>
      <form class="row" method="post" action="/users/delete"><input type="hidden" name="csrf" value="{{$.CSRF}}"><input type="hidden" name="id" value="{{.ID}}">
        <label class="check"><input type="checkbox" name="confirm" value="yes" required> Delete {{.DisplayName}} and all their data</label>
        <button class="danger">Delete</button></form>
    </div></details>
  </div>
  {{end}}
  {{else}}<div class="card"><p class="dim" style="margin:0">No accounts yet.</p></div>{{end}}
  <p class="dim small">Today's steps use the server's date ({{.Today}}, {{.Zone}}).</p>

{{else if eq .Page "challenges"}}
  <h1>Challenges</h1>
  {{if .Challenges}}
  {{range .Challenges}}
  <div class="card">
    <div class="row spread">
      <div><h2 style="margin:0">{{.Name}}</h2><span class="dim small">{{short .Start .End}} · started by {{.Creator}} · {{.Joined}} in{{if .Invited}}, {{.Invited}} invited{{end}}</span></div>
      {{if eq .State "active"}}<span class="pill">Active</span>{{else if eq .State "upcoming"}}<span class="pill grey">Upcoming</span>{{else}}<span class="pill grey">Finished</span>{{end}}
    </div>
    {{if .Top}}<ol class="board">{{range .Top}}<li>{{.DisplayName}} — <b>{{num .Total}}</b> steps</li>{{end}}</ol>{{end}}
    <details style="margin-top:8px"><summary>Delete</summary>
      <form class="row actions" method="post" action="/challenges/delete"><input type="hidden" name="csrf" value="{{$.CSRF}}"><input type="hidden" name="id" value="{{.ID}}">
        <label class="check"><input type="checkbox" name="confirm" value="yes" required> Delete this challenge for everyone</label>
        <button class="danger">Delete</button></form>
    </details>
  </div>
  {{end}}
  {{else}}<div class="card"><p class="dim" style="margin:0">No challenges yet. People create them from the Friends tab in the app.</p></div>{{end}}

{{else if eq .Page "settings"}}
  <h1>Settings</h1>
  <div class="card">
    <h2>Admin password</h2>
    <form method="post" action="/settings/password" style="display:grid;gap:10px;max-width:380px"><input type="hidden" name="csrf" value="{{.CSRF}}">
      <input type="password" name="current" placeholder="Current password" required autocomplete="current-password">
      <input type="password" name="password" placeholder="New password (10+ characters)" minlength="10" required autocomplete="new-password">
      <input type="password" name="password2" placeholder="Repeat new password" minlength="10" required autocomplete="new-password">
      <div><button>Change password</button></div>
    </form>
  </div>
  <div class="card">
    <h2>Backup</h2>
    <p class="dim small">Downloads every account, friendship, step total and challenge as one file. It contains password hashes, so store it somewhere private.</p>
    <a class="btn ghost" href="/backup">Download backup</a>
  </div>
  <div class="card">
    <h2>Server</h2>
    <table>
      <tr><td class="dim">Version</td><td>{{.Version}}</td></tr>
      <tr><td class="dim">Data file</td><td>{{.DataSize}}</td></tr>
      <tr><td class="dim">Server date</td><td>{{.Today}} ({{.Zone}})</td></tr>
    </table>
    <p class="dim small">This panel only answers on your home network and is never reachable through the app's public address.</p>
  </div>
{{end}}
</main>
{{end}}
</body>
</html>`
