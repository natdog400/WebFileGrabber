import os
import sys
import re
import urllib.parse
from mitmproxy import http

def sanitize_name(name):
    return re.sub(r'[<>:"/\\|?*]', '_', name)

class SwfSaver:
    def __init__(self, outdir, host_filter, host_includes, host_excludes, includes, excludes, ct_includes, mirror, save_all=False):
        self.outdir = outdir
        self.host_filter = host_filter
        self.host_includes = [t for t in (host_includes or []) if t]
        self.host_excludes = [t for t in (host_excludes or []) if t]
        self.includes = [t for t in (includes or []) if t]
        self.excludes = [t for t in (excludes or []) if t]
        self.ct_includes = [t for t in (ct_includes or []) if t]
        self.mirror = mirror
        self.save_all = bool(save_all)
        self.seen = set()

    def response(self, flow: http.HTTPFlow):
        try:
            url = flow.request.url or ""
            hu = urllib.parse.urlparse(url).hostname or ""
            if not self.save_all:
                if self.host_filter:
                    if not (hu == self.host_filter or hu.endswith("." + self.host_filter)):
                        return
                if self.host_includes:
                    hit = False
                    for tok in self.host_includes:
                        if tok == "*":
                            hit = True
                            break
                        if tok and (hu == tok or hu.endswith("." + tok)):
                            hit = True
                            break
                    if not hit:
                        return
                if self.host_excludes:
                    for tok in self.host_excludes:
                        if tok and (hu == tok or hu.endswith("." + tok)):
                            return
            ct = (flow.response.headers.get("content-type", "")).lower()
            url_l = url.lower()
            cd = (flow.response.headers.get("content-disposition", "")).lower()
            name_in_cd = "filename=" in cd and ".swf" in cd
            is_swf = url_l.endswith(".swf") or ".swf" in url_l or ("application/x-shockwave-flash" in ct) or name_in_cd
            def match_filters():
                if self.save_all:
                    return True
                if self.includes:
                    inc_hit = False
                    for tok in self.includes:
                        if tok == "*":
                            inc_hit = True
                            break
                        if tok and (tok in url_l or tok in cd):
                            inc_hit = True
                            break
                    if not inc_hit:
                        return False
                if self.ct_includes:
                    if not any(t in ct for t in self.ct_includes):
                        return False
                if self.excludes:
                    for tok in self.excludes:
                        if tok and (tok in url_l or tok in ct or tok in cd):
                            return False
                return True
            should_save = match_filters()
            if not should_save:
                if not is_swf:
                    body_probe = flow.response.content or b""
                    sig = body_probe[:3]
                    if sig not in (b"FWS", b"CWS", b"ZWS"):
                        return
                    print("Signature-detected SWF:", url)
            if url in self.seen:
                return
            self.seen.add(url)
            body = flow.response.content or b""
            path = urllib.parse.urlparse(url).path
            base = os.path.basename(path) or "file.swf"
            base = sanitize_name(base)
            if base == "file.swf":
                cd_hdr = flow.response.headers.get("content-disposition", "")
                m = re.search(r'filename="?([^";]+)"?', cd_hdr, re.IGNORECASE)
                if m:
                    cand = sanitize_name(m.group(1))
                    if cand:
                        base = cand
                if base == "file.swf":
                    try:
                        up = urllib.parse.urlparse(url)
                        qs = urllib.parse.parse_qsl(up.query, keep_blank_values=True)
                        for _, val in qs:
                            if val and ".swf" in val.lower():
                                cand = sanitize_name(os.path.basename(val))
                                if cand:
                                    base = cand
                                    break
                    except Exception:
                        pass
            # derive extension from URL if present
            if not base.lower().endswith(".swf"):
                # use original extension if any
                _, ext = os.path.splitext(base)
                if not ext:
                    # fallback by content-type (minimal mapping)
                    if "image/jpeg" in ct:
                        base = base + ".jpg"
                    elif "image/png" in ct:
                        base = base + ".png"
                    elif "audio/mpeg" in ct or "audio/mp3" in ct:
                        base = base + ".mp3"
                    elif "application/json" in ct:
                        base = base + ".json"
                    elif "text/html" in ct:
                        base = base + ".html"
                    elif "text/css" in ct:
                        base = base + ".css"
                    elif "application/javascript" in ct or "text/javascript" in ct:
                        base = base + ".js"
                    else:
                        base = base + ".bin"
            if self.mirror:
                host = urllib.parse.urlparse(url).hostname or ""
                dir_path = os.path.dirname(path)
                safe_parts = [sanitize_name(p) for p in dir_path.split('/') if p]
                target_dir = os.path.join(self.outdir, sanitize_name(host), *safe_parts)
            else:
                target_dir = self.outdir
            os.makedirs(target_dir, exist_ok=True)
            fp = os.path.join(target_dir, base)
            with open(fp, "wb") as f:
                f.write(body)
            print("Saved", fp)
        except Exception:
            pass

addons = []
def build_addon(args):
    outdir = os.environ.get("SWF_OUTDIR") or (args[1] if len(args) > 1 else os.getcwd())
    host = os.environ.get("SWF_HOST") or (args[2] if len(args) > 2 else "")
    host_includes = (os.environ.get("SWF_HOST_INCLUDES") or (args[3] if len(args) > 3 else ""))
    host_excludes = (os.environ.get("SWF_HOST_EXCLUDES") or (args[4] if len(args) > 4 else ""))
    includes = (os.environ.get("SWF_INCLUDES") or (args[5] if len(args) > 5 else ""))
    excludes = (os.environ.get("SWF_EXCLUDES") or (args[6] if len(args) > 6 else ""))
    ct_includes = (os.environ.get("SWF_CT_INCLUDES") or (args[7] if len(args) > 7 else ""))
    mirror = os.environ.get("SWF_MIRROR")
    if mirror is None:
        mirror = (args[8] if len(args) > 8 else "0")
    save_all = os.environ.get("SWF_SAVE_ALL") or "0"
    host_includes = (host_includes.split(',') if host_includes else [])
    host_excludes = (host_excludes.split(',') if host_excludes else [])
    includes = (includes.split(',') if includes else [])
    excludes = (excludes.split(',') if excludes else [])
    ct_includes = (ct_includes.split(',') if ct_includes else [])
    mirror = (str(mirror) == '1')
    save_all = (str(save_all) == '1')
    return [SwfSaver(outdir, host, host_includes, host_excludes, includes, excludes, ct_includes, mirror, save_all)]

addons = []
if __name__ == "__main__":
    addons = build_addon(sys.argv)
else:
    addons = build_addon(sys.argv)
