"""Generate a dedicated transparent cyber logo for DnsProbe."""

from PIL import Image, ImageDraw


def create_dns_logo(size=(264, 287)):
    w, h = size
    scale = 4
    sw, sh = w * scale, h * scale

    img = Image.new("RGBA", (sw, sh), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)

    cx = sw // 2
    cy = int(sh * 0.46)

    # Shield polygon
    top = int(sh * 0.08)
    bottom = int(sh * 0.94)
    left = int(sw * 0.10)
    right = int(sw * 0.90)
    mid_y = int(sh * 0.58)

    shield_pts = [
        (left, top + int(sh * 0.08)),
        (left + int(sw * 0.15), top),
        (cx, top + int(sh * 0.04)),
        (right - int(sw * 0.15), top),
        (right, top + int(sh * 0.08)),
        (right, mid_y),
        (cx, bottom),
        (left, mid_y),
    ]

    draw.polygon(shield_pts, fill=(12, 28, 52, 245), outline=(0, 210, 255, 255), width=int(10 * scale))

    # Inner decorative border
    inner_pts = [
        (left + 24, top + int(sh * 0.08) + 12),
        (left + int(sw * 0.15) + 16, top + 24),
        (cx, top + int(sh * 0.04) + 24),
        (right - int(sw * 0.15) - 16, top + 24),
        (right - 24, top + int(sh * 0.08) + 12),
        (right - 24, mid_y - 12),
        (cx, bottom - 32),
        (left + 24, mid_y - 12),
    ]
    draw.polygon(inner_pts, fill=(8, 20, 38, 255), outline=(147, 51, 234, 180), width=int(3 * scale))

    # Globe / DNS network grid
    globe_r = int(sw * 0.28)
    draw.ellipse([cx - globe_r, cy - globe_r, cx + globe_r, cy + globe_r], outline=(0, 210, 255, 180), width=int(3 * scale))
    draw.ellipse([cx - int(globe_r * 0.5), cy - globe_r, cx + int(globe_r * 0.5), cy + globe_r], outline=(0, 210, 255, 130), width=int(2 * scale))
    draw.line([(cx - globe_r, cy), (cx + globe_r, cy)], fill=(0, 210, 255, 130), width=int(2 * scale))
    draw.line([(cx, cy - globe_r), (cx, cy + globe_r)], fill=(0, 210, 255, 130), width=int(2 * scale))

    # Central DNS Search / Magnifier Probe node
    probe_r = int(sw * 0.11)
    probe_cx = cx + int(sw * 0.06)
    probe_cy = cy + int(sh * 0.04)
    draw.ellipse([probe_cx - probe_r, probe_cy - probe_r, probe_cx + probe_r, probe_cy + probe_r], outline=(255, 214, 0, 255), width=int(4 * scale))
    draw.line([(probe_cx + int(probe_r * 0.7), probe_cy + int(probe_r * 0.7)), (probe_cx + int(probe_r * 1.5), probe_cy + int(probe_r * 1.5))], fill=(255, 214, 0, 255), width=int(6 * scale))

    final_img = img.resize(size, Image.Resampling.LANCZOS)
    return final_img


if __name__ == "__main__":
    logo = create_dns_logo((264, 287))
    logo.save("assets/logos/dnsprobe.png", "PNG")
    badge = logo.resize((128, 128), Image.Resampling.LANCZOS)
    badge.save("assets/logos/badges/dnsprobe_badge.png", "PNG")
    print("[✔] Successfully created assets/logos/dnsprobe.png and badge!")

