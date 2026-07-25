"""Composite the VULN HUNTER banner from the Golden Eagle source photo.

Source: "Golden Eagle in flight - 5.jpg", Tony Hisgett, CC-BY-2.0,
https://commons.wikimedia.org/wiki/File:Golden_Eagle_in_flight_-_5.jpg
"""
from PIL import Image, ImageDraw, ImageFont, ImageEnhance

SRC = "golden-eagle-source.jpg"
OUT = "banner.png"
W, H = 1280, 400

img = Image.open(SRC).convert("RGB")

# Top-anchored full-width crop: keeps the eagle's head/eye (upper-left of
# the source) in frame instead of a center-crop that cuts straight through
# the wing and misses the head entirely.
target_ratio = W / H
crop_h = int(img.width / target_ratio)
img = img.crop((0, 0, img.width, crop_h))
img = img.resize((W, H), Image.LANCZOS)

# Darken slightly for text legibility, then lay a dark-red gradient (matches
# the repo's existing capsule-render banner colors: 7F1D1D -> DC2626).
img = ImageEnhance.Brightness(img).enhance(0.75)
gradient = Image.new("RGB", (W, H))
top, bottom = (127, 29, 29), (30, 10, 10)
for y in range(H):
    t = y / H
    row = tuple(int(top[i] * (1 - t) + bottom[i] * t) for i in range(3))
    ImageDraw.Draw(gradient).line([(0, y), (W, y)], fill=row)
img = Image.blend(img, gradient, alpha=0.45)

draw = ImageDraw.Draw(img)
try:
    font_big = ImageFont.truetype("C:/Windows/Fonts/arialbd.ttf", 90)
    font_small = ImageFont.truetype("C:/Windows/Fonts/arial.ttf", 24)
except OSError:
    font_big = ImageFont.load_default()
    font_small = font_big

title = "VULN HUNTER"
subtitle = "Real static analysis for detection, Claude for triage — never the reverse"

def centered(text, font, y, fill, shadow=True):
    bbox = draw.textbbox((0, 0), text, font=font)
    tw = bbox[2] - bbox[0]
    x = (W - tw) // 2
    if shadow:
        draw.text((x + 3, y + 3), text, font=font, fill=(0, 0, 0, 160))
    draw.text((x, y), text, font=font, fill=fill)

centered(title, font_big, 250, (255, 255, 255))
centered(subtitle, font_small, 355, (240, 220, 220))

img.save(OUT)
print(f"Wrote {OUT}: {img.size}")
