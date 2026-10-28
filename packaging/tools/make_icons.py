"""Dev-time helper: renders the LLM Vault app icon (shield + keyhole) to PNG/ICO/ICNS-ready PNGs.
Not part of the shipped application. Usage: python packaging/tools/make_icons.py"""
from pathlib import Path
from PIL import Image, ImageDraw

ROOT = Path(__file__).resolve().parents[2]
NAVY, TEAL, BLUE = (15, 31, 61), (20, 184, 166), (37, 99, 235)

def render(size: int) -> Image.Image:
    s = 4  # supersampling
    W = size * s
    img = Image.new("RGBA", (W, W), (0, 0, 0, 0))
    # gradient square background with rounded corners
    grad = Image.new("RGBA", (W, W))
    gd = ImageDraw.Draw(grad)
    for y in range(W):
        t = y / W
        c = tuple(int(TEAL[i] * (1 - t) + BLUE[i] * t) for i in range(3))
        gd.line([(0, y), (W, y)], fill=c + (255,))
    mask = Image.new("L", (W, W), 0)
    ImageDraw.Draw(mask).rounded_rectangle([0, 0, W - 1, W - 1], radius=int(W * 0.22), fill=255)
    img.paste(grad, (0, 0), mask)
    d = ImageDraw.Draw(img)
    # navy shield
    cx = W / 2
    top, bot, half = W * 0.16, W * 0.88, W * 0.31
    shield = [(cx, top), (cx + half, top + W * 0.09), (cx + half, W * 0.50),
              (cx + half * 0.8, W * 0.68), (cx, bot), (cx - half * 0.8, W * 0.68),
              (cx - half, W * 0.50), (cx - half, top + W * 0.09)]
    d.polygon(shield, fill=NAVY + (255,))
    # keyhole
    r = W * 0.085
    ky = W * 0.44
    d.ellipse([cx - r, ky - r, cx + r, ky + r], fill=TEAL + (255,))
    d.polygon([(cx - r * 0.55, ky + r * 0.4), (cx + r * 0.55, ky + r * 0.4), (cx + r * 0.9, W * 0.68), (cx - r * 0.9, W * 0.68)], fill=TEAL + (255,))
    return img.resize((size, size), Image.LANCZOS)

def main() -> None:
    out_ui = ROOT / "ui" / "icons"
    out_assets = ROOT / "assets"
    out_assets.mkdir(exist_ok=True)
    big = render(512)
    big.save(out_assets / "icon-512.png")
    render(256).save(out_ui / "app.png")
    render(256).save(out_assets / "icon-256.png")
    render(128).save(out_assets / "icon-128.png")
    big.save(out_assets / "llmvault.ico", sizes=[(16, 16), (24, 24), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)])
    print("icons written")

if __name__ == "__main__":
    main()
