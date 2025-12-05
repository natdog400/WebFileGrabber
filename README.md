# SWF Files Downloader

A desktop tool to capture and save SWF and other assets from websites using three capture modes: embedded browser (Playwright), system proxy (mitmproxy), and Edge CDP attachment.

## Features
- Multiple capture modes: `Browser`, `Proxy (system Edge)`, `Connect (Edge CDP)`
- Fine-grained filtering by URL tokens, content-type, and host
- Optional domain restriction to the entered URL
- Optional mirroring of URL path into output folders
- HAR/SAZ import to extract assets offline
- Convenience actions for Edge CDP launch/attach and proxy certificate install
- Settings persistence to a user profile path

## Settings
All settings are bound to the UI and persisted at `~/.swf_downloader/settings.json` (`python-app/app.py:747`). The UI is organized into tabs:

- Main → Capture, Filters, Advanced (`python-app/app.py:52–73`)
- Logs (separate tab for output) (`python-app/app.py:44–52`)

- `URL` — Target page to navigate or domain to restrict (`python-app/app.py:34`).
- `Save to` — Destination folder for downloaded files (`python-app/app.py:38`).
- `Restrict to entered domain` — Only capture requests on the entered host or its subdomains (`python-app/app.py:42`).
- `Capture mode` — `playwright`, `proxy`, or `cdp` (`python-app/app.py:45–48`).
- `Browser engine` — `chromium`, `edge`, or `palemoon` (`python-app/app.py:49–53`).
- `Edge executable` — Path to `msedge.exe` when launching Edge via Playwright (`python-app/app.py:54–57`).
- `CDP port` — Port for Edge remote debugging; `0`/`auto` to auto-assign (`python-app/app.py:58–60`).
- `Enable Ruffle extension (Browser mode)` — Load unpacked Ruffle extension (`python-app/app.py:61–62`).
- `Ruffle extension folder` — Path to unpacked Ruffle extension (must contain `manifest.json`) (`python-app/app.py:63–66`).
- `Verify Ruffle (demo) before URL` — Navigate to demo and check extension presence (`python-app/app.py:67–68`).
- `Require Ruffle to start` — Abort if Ruffle verification fails (`python-app/app.py:69–70`).
- `Include filters (comma)` — Tokens matched in URL or `content-disposition`; `*` acts as wildcard (`python-app/app.py:71–73`).
- `Exclude filters (comma)` — Tokens to block; matched in URL, `content-type`, or `content-disposition` (`python-app/app.py:74–76`).
- `Content-Types (comma)` — Allowed content-type substrings (e.g. `application/x-shockwave-flash`) (`python-app/app.py:77–79`).
- `Host includes (comma)` — Allowed hosts or parent domains; match exact or subdomain; `*` wildcard (`python-app/app.py:80–83`).
- `Host excludes (comma)` — Blocked hosts or parent domains (`python-app/app.py:83–86`).
- `Mirror URL path into folders` — Create nested folders per host/path (`python-app/app.py:112–124`).
- `Save all via Proxy` — In Proxy mode, save all response bodies routed through the proxy (`python-app/app.py:122–123`).

Saved keys (for reference): `url`, `dir`, `domain_only`, `capture_mode`, `browser_engine`, `edge_path`, `ruffle_enable`, `ruffle_path`, `includes`, `excludes`, `ct_includes`, `host_includes`, `host_excludes`, `mirror`, `cdp_port` (`python-app/app.py:752–769`).

## Buttons & Actions
- `Start` — Begin capture in the selected mode (`python-app/app.py:84–86`, handler `start` at `python-app/app.py:180`).
- `Stop` — Stop current capture process/thread (`python-app/app.py:86–88`, handler `stop` at `python-app/app.py:267`).
- `Install proxy certificate` — Install mitmproxy CA to user Trusted Root (`python-app/app.py:88–90`, logic `python-app/app.py:376–416`).
- `Open cert folder` — Open `~/.mitmproxy` in Explorer (`python-app/app.py:90–91`, logic `python-app/app.py:366–374`).
- `Launch Edge (CDP)` — Launch Edge with `--remote-debugging-port` (`python-app/app.py:92–93`, logic `python-app/app.py:289`).
- `Launch Edge (CDP auto)` — Launch Edge with auto-assigned CDP port (`python-app/app.py:100`, logic `python-app/app.py:321`).
- `Attach Now (CDP)` — Attach immediately to an active Edge CDP session (`python-app/app.py:101`, logic `python-app/app.py:328`).
- `Start Proxy Only` — Start the proxy capture without launching a browser (`python-app/app.py:104–110`, logic `python-app/app.py:497`).
- `Verify CDP` — Attempt to connect to CDP endpoints and report status (`python-app/app.py:98–99`, logic `python-app/app.py:628`).
- `Kill Edge` — Force-terminate `msedge.exe` processes (`python-app/app.py:97–98`, logic `python-app/app.py:614`).
- `Import HAR` — Import `.har` or `.json` and save matching assets (`python-app/app.py:95–96`, dialog `python-app/app.py:142`).
- `Import SAZ` — Import `.saz` or `.zip` and save matching assets (`python-app/app.py:96–97`, dialog `python-app/app.py:160`).
- `Save settings` / `Load settings` — Persist/retrieve settings JSON (`python-app/app.py:93–95`, logic `python-app/app.py:752`, `python-app/app.py:777`).
- `Check Edge Policy` — Show DevTools policy from registry (`python-app/app.py:99`, logic `python-app/app.py:720`).

## Capture Modes
- Browser (Playwright) — Launch Chromium/Edge; listen to `response` events and save bodies (`python-app/app.py:407–613`).
  - Ruffle extension support and demo verification (`python-app/app.py:452–473`).
  - Filtering by host includes/excludes, domain restriction, URL/content-disposition/content-type (`python-app/app.py:495–549`).
  - Optional mirroring to `Save to/host/path/...` (`python-app/app.py:570–579`).
- Proxy (mitmproxy) — Start mitmproxy with addon script; optionally launch Edge with proxy (`python-app/app.py:802–840`).
  - Addon script `python-app/mitm_swf.py` enforces host filters and match rules; supports `Save all via Proxy` (`python-app/mitm_swf.py:10–43`).
  - Edge launched with `--proxy-server=127.0.0.1:8888` when engine is Edge (`python-app/app.py:830–844`).
  - Proxy receives settings via environment: `SWF_OUTDIR`, `SWF_HOST`, `SWF_HOST_INCLUDES`, `SWF_HOST_EXCLUDES`, `SWF_INCLUDES`, `SWF_EXCLUDES`, `SWF_CT_INCLUDES`, `SWF_MIRROR`, `SWF_SAVE_ALL` (`python-app/app.py:816–826`, `python-app/mitm_swf.py:145–164`).
- Connect (Edge CDP) — Attach to an existing Edge remote debugging session (`python-app/app.py:1055–1260`).
  - Prefers `DevToolsActivePort` auto-detected profile path; falls back to `host:port` (`python-app/app.py:1078–1150`).
  - Filtering and saving logic mirrors Browser mode (`python-app/app.py:1149–1229`).

## Filters
- Host includes/excludes — Match exact host or any subdomain of a token; `*` in includes matches all (`python-app/app.py:513`, `python-app/app.py:1240`).
- Domain restriction — If enabled, only `URL` host and its subdomains are allowed (`python-app/app.py:500–505`, `python-app/app.py:1165–1168`).
- Include filters — Tokens matched in URL or `content-disposition`; `*` wildcard (`python-app/app.py:529–538`).
- Exclude filters — Tokens matched in URL, `content-type`, or `content-disposition` (`python-app/app.py:544–548`).
- Content-Types — Require any token to be present in `content-type` (`python-app/app.py:540–543`).
- Signature fallback — If filters don’t hit, detect SWF via body signature `FWS/CWS/ZWS` (`python-app/app.py:551–557`, `python-app/app.py:1196–1201`). In Proxy mode, when the URL path is generic, the addon attempts to derive SWF filename from query parameters (e.g. `gamemovie=...swf`) (`python-app/mitm_swf.py:84–100`).

## Importers
- HAR — Parses entries, applies filters, decodes response body, saves output (`python-app/app.py:896–940`).
- SAZ — Parses Fiddler archive groups, applies filters, saves output (`python-app/app.py:994–1053`).

## File Saving
- Base name from URL path; sanitized to remove unsafe characters (`python-app/app.py:560–569`).
- If `content-disposition` includes `filename=`, uses that (`python-app/app.py:563–569`).
- Proxy addon adds minimal extension inference for non-SWF types (`python-app/mitm_swf.py:59–83`).
- Mirroring builds `Save to/<host>/<path folders>/filename` (`python-app/app.py:571–579`, `python-app/mitm_swf.py:84–94`).

## Paths & Profiles
- Settings: `~/.swf_downloader/settings.json` (`python-app/app.py:747–750`).
- Playwright persistent context (when loading Ruffle): `~/.swf_downloader/pw_profile` (`python-app/app.py:456–463`).
- Edge CDP profile: `~/.swf_downloader/edge_cdp_profile` (`python-app/app.py:306–313`).
- Edge Proxy profile: `~/.swf_downloader/edge_proxy_profile` (`python-app/app.py:818–824`).
- Mitmproxy certificates: `~/.mitmproxy` (`python-app/app.py:357–365`).

## Function Reference (app.py)
- `choose_dir` — Set save directory via dialog (`python-app/app.py:119`).
- `_choose_dir` — Helper to set any `StringVar` with a directory (`python-app/app.py:124`).
- `_choose_file` — Helper to set any `StringVar` with a file path (`python-app/app.py:129`).
- `_normalize_url` — Ensure input has a scheme, default `https://` (`python-app/app.py:134`).
- `import_har_dialog` — Start HAR import thread (`python-app/app.py:142`).
- `import_saz_dialog` — Start SAZ import thread (`python-app/app.py:160`).
- `log_line` — Append line to UI log (`python-app/app.py:176`).
- `start` — Begin capture with chosen mode and filters (`python-app/app.py:180`).
- `stop` — Stop processes/threads and reset UI state (`python-app/app.py:267`).
- `launch_edge_cdp` — Launch Edge with remote debugging (`python-app/app.py:289`).
- `launch_edge_cdp_auto` — Same but auto port (`python-app/app.py:321`).
- `attach_now_cdp` — Immediately attach to current CDP session (`python-app/app.py:328`).
- `_cert_candidates` — Return mitmproxy cert candidate paths (`python-app/app.py:357`).
- `open_cert_folder` — Open cert folder in Explorer (`python-app/app.py:366`).
- `install_proxy_cert` — Install mitmproxy CA to Trusted Root (`python-app/app.py:376`).
- `_run_capture` — Entry to async Playwright capture (`python-app/app.py:418`).
- `_capture_async` — Playwright implementation with filtering/saving (`python-app/app.py:421`).
- `kill_edge_tasks` — Kill Edge processes (`python-app/app.py:614`).
- `verify_cdp` — Check CDP reachable over ws/http (`python-app/app.py:628`).
- `_verify_cdp_run` — Thread entry to `_verify_cdp_async` (`python-app/app.py:673`).
- `check_edge_policy` — Read DevTools policy in registry (`python-app/app.py:720`).
- `_settings_path` — Resolve settings JSON path (`python-app/app.py:747`).
- `save_settings` — Persist current UI settings (`python-app/app.py:752`).
- `load_settings` — Load saved settings (`python-app/app.py:777`).
- `_run_proxy_capture` — Start mitmproxy and launch browser with proxy (`python-app/app.py:802`).
- `_run_cdp_capture` — Entry to async CDP capture (`python-app/app.py:893`).
- `_run_import_har` — HAR parsing and saving (`python-app/app.py:896`).
- `_run_import_saz` — SAZ parsing and saving (`python-app/app.py:994`).
- `_capture_cdp_async` — CDP attachment and filtering/saving (`python-app/app.py:1123`).
- `main` — Tk application entrypoint (`python-app/app.py:1254–1260`).

## Proxy Addon (mitm_swf.py)
- `SwfSaver` — mitmproxy addon enforcing host and asset filters, saves bodies (`python-app/mitm_swf.py:11–48`).
- `build_addon` — Parse script args and construct addon list (`python-app/mitm_swf.py:129–137`).

## Notes
- Host includes/excludes match either exact domain or any subdomain of a token.
- When `Restrict to entered domain` is on, domain restriction applies before other filters.
- Use `*` in `Host includes` to allow all hosts while using other filters.

### HTTPS Decryption
- Install the proxy CA to enable HTTPS body capture:
  - Open `http://mitm.it` in a proxied browser and follow the platform instructions.
  - On Windows, you can also run: `certutil.exe -addstore root mitmproxy-ca-cert.cer` to add it to Trusted Root.
  - After installation, the app’s proxy status banner updates (see `update_proxy_status` in `python-app/app.py:483`).
