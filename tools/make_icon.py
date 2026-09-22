"""Render the LinkTest logo to assets/linktest.png and assets/linktest.ico.

Run once (needs Pillow); the results are committed so builds never need it.
The drawing matches the inline SVG in ui/index.html: a #0b6ef5 rounded square
with a white zig-zag "speed" line.
"""
import os
import sys

try:
    from PIL import Image, ImageDraw
except ImportError:
    sys.exit("Pillow is required: pip install pillow")

HERE = os.path.dirname(os.path.abspath(__file__))
ASSETS = os.path.join(os.path.dirname(HERE), "assets")
BLUE = (11, 110, 245, 255)
WHITE = (255, 255, 255, 255)
# SVG coordinates on a 32-unit grid.
POINTS = [(7, 20), (12, 12), (16, 18), (19, 14), (25, 22)]


def render(size: int) -> Image.Image:
    ss = 8  # supersample
    big = size * ss
    s = big / 32.0
    img = Image.new("RGBA", (big, big), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    d.rounded_rectangle([0, 0, big - 1, big - 1], radius=8 * s, fill=BLUE)
    pts = [(x * s, y * s) for x, y in POINTS]
    w = 3 * s
    d.line(pts, fill=WHITE, width=int(w), joint="curve")
    for x, y in (pts[0], pts[-1]):  # round caps
        d.ellipse([x - w / 2, y - w / 2, x + w / 2, y + w / 2], fill=WHITE)
    return img.resize((size, size), Image.LANCZOS)


def main() -> int:
    os.makedirs(ASSETS, exist_ok=True)
    png = render(256)
    png.save(os.path.join(ASSETS, "linktest.png"))
    sizes = [16, 24, 32, 48, 64, 128, 256]
    frames = [render(n) for n in sizes]
    frames[-1].save(os.path.join(ASSETS, "linktest.ico"), format="ICO",
                    sizes=[(n, n) for n in sizes], append_images=frames[:-1])
    # macOS icon (Pillow writes ICNS on every platform since 8.1)
    big = render(1024)
    big.save(os.path.join(ASSETS, "linktest.icns"), format="ICNS",
             append_images=[render(n) for n in (16, 32, 64, 128, 256, 512)])
    print("wrote", os.path.join(ASSETS, "linktest.png"), ", linktest.ico and linktest.icns")
    return 0


if __name__ == "__main__":
    sys.exit(main())
