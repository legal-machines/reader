#!/usr/bin/env python3
"""The Mail app's own stylesheet and the icons the reader uses, copied from
the Mail app's source (../mail/webmail/src) into mail.css and icons.mjs, so
that a message opened here looks exactly like one in the Mail app. From the
source on this computer, never from the mail server: the server's hosting
company must not choose how the reader looks (it could hide a warning)."""
import json
import os
import re

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(HERE, "..", "mail", "webmail", "src")
ICONS = ["attach", "image", "download", "open", "lock", "lock_open", "warning", "key"]

assets = open(os.path.join(SRC, "Assets.h")).read()
start = assets.index("inline const std::string &app_css()")
begin = assets.index('R"CSS(', start) + len('R"CSS(')
css = assets[begin:assets.index(')CSS"', begin)]
if re.search(r"url\((?!\s*['\"]?data:)", css) or "@import" in css:
    raise SystemExit("make-styles: the Mail app's stylesheet loads something from elsewhere")
with open(os.path.join(HERE, "mail.css"), "w") as f:
    f.write("/* The Mail app's stylesheet, copied by make-styles.py from webmail/src/Assets.h. Do not edit here. */\n" + css.strip() + "\n")

# An HTML message's own page in the Mail app (the /body route): its stylesheet.
routes = open(os.path.join(SRC, "RoutesMail.cpp")).read()
at = routes.index('page_route("/body"')
setbody = routes[routes.index("res->setBody(", at):routes.index(");", routes.index("res->setBody(", at))]
joined = "".join(re.findall(r'"((?:[^"\\]|\\.)*)"', setbody)).replace('\\"', '"')
letter_css = re.search(r"<style>(.*?)</style>", joined).group(1)
with open(os.path.join(HERE, "letter.mjs"), "w") as f:
    f.write("// The stylesheet of an HTML message's page in the Mail app (its /body route), copied by make-styles.py. Do not edit here.\n"
            f"export const LETTER_CSS = {json.dumps(letter_css)};\n")

icons = open(os.path.join(SRC, "Icons.h")).read()
paths = {name: re.search(r'\{"' + name + r'", "([^"]+)"\}', icons).group(1) for name in ICONS}
with open(os.path.join(HERE, "icons.mjs"), "w") as f:
    f.write("// The Mail app's icons (Material, 24 px), copied by make-styles.py from webmail/src/Icons.h. Do not edit here.\n"
            f"const PATHS = {json.dumps(paths, indent=1)};\n"
            "export const icon = name => PATHS[name] ? `<svg class=\"i\" viewBox=\"0 0 24 24\" aria-hidden=\"true\" focusable=\"false\"><path d=\"${PATHS[name]}\"/></svg>` : '';\n")
print(f"make-styles: mail.css ({len(css)} bytes), icons.mjs ({len(paths)} icons)")
