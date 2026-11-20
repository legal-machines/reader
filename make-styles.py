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
ICONS = ["attach", "image", "download", "open", "lock", "lock_open", "warning", "key", "close", "delete", "pilcrow", "undo", "redo", "text_size", "bold", "italic",
         "underline", "strike", "text_color", "align_left", "align_center", "align_right", "align_justify", "numbers", "bullets",
         "indent_less", "indent_more", "quote", "link", "emoji", "table", "clear", "verified_user", "shield"]


def by_window(css):
    """The Mail app's rules for narrow windows (@media (max-width:840px) and
    the like) keyed to classes on the root instead (narrow, phone, wide): a
    frame is narrower than the window it is in, and must look as the page
    around it does, so the page tells each frame how wide the window is."""
    names = {"(max-width:840px)": "narrow", "(max-width:640px)": "phone", "(min-width:841px)": "wide"}

    def split(text, sep):
        out, depth, start = [], 0, 0
        for i, c in enumerate(text):
            if c in "([":
                depth += 1
            elif c in ")]":
                depth -= 1
            elif c == sep and depth == 0:
                out.append(text[start:i])
                start = i + 1
        out.append(text[start:])
        return out

    def prefix(selector, cls):
        s = selector.strip()
        if s.startswith(":root"):
            return ":root." + cls + s[5:]
        if re.match(r"html(?![\w-])", s):
            return "html." + cls + s[4:]
        return ":root." + cls + " " + s

    def blocks(text):
        """Top-level (head, body) pairs: a rule or an at-rule with its block."""
        out, i = [], 0
        while i < len(text):
            j = text.find("{", i)
            if j < 0:
                break
            depth, k = 1, j + 1
            while depth and k < len(text):
                depth += {"{": 1, "}": -1}.get(text[k], 0)
                k += 1
            out.append((text[i:j], text[j + 1:k - 1]))
            i = k
        return out

    def scoped(text, cls):
        out = ""
        for head, body in blocks(text):
            h = head.strip()
            if h.startswith("@"):
                out += h + "{" + scoped(body, cls) + "}"
            else:
                out += ",".join(prefix(x, cls) for x in split(h, ",")) + "{" + body + "}"
        return out

    css = re.sub(r"/\*.*?\*/", "", css, flags=re.S)
    out = ""
    for head, body in blocks(css):
        h = re.sub(r"\s+", "", head.split("*/")[-1]) if head.strip().startswith("/*") else re.sub(r"\s+", "", head)
        comment = head[:head.rfind("*/") + 2] if "*/" in head and not head.strip().startswith("@") and head.strip().startswith("/*") else ""
        cond = h[len("@media"):] if h.startswith("@media") else None
        if cond in names:
            out += comment + scoped(body, names[cond]) + "\n"
        else:
            out += head + "{" + body + "}"
    return out


assets = open(os.path.join(SRC, "Assets.h")).read()
start = assets.index("inline const std::string &app_css()")
begin = assets.index('R"CSS(', start) + len('R"CSS(')
css = assets[begin:assets.index(')CSS"', begin)]
if re.search(r"url\((?!\s*['\"]?data:)", css) or "@import" in css:
    raise SystemExit("make-styles: the Mail app's stylesheet loads something from elsewhere")
with open(os.path.join(HERE, "mail.css"), "w") as f:
    f.write("/* The Mail app's stylesheet, copied by make-styles.py from webmail/src/Assets.h, its rules for narrow windows\n"
            "   keyed to the window's width as the page tells it (html.narrow, .phone, .wide). Do not edit here. */\n" + by_window(css).strip() + "\n")

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
