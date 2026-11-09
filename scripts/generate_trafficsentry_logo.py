"""Generate a dedicated transparent cyber logo for TrafficSentry."""

import math
from PIL import Image, ImageDraw, ImageFilter


def create_traffic_logo(size=(264, 287)):
    w, h = size
    # High resolution supersampling for smooth antialiased edges
    scale = 4
    sw, sh = w * scale, h * scale

    img = Image.new("RGBA", (sw, sh), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)

    cx = sw // 2
    cy = int(sh * 0.46)
    r = int(sw * 0.42)

    # Shield polygon coordinates
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

    # Draw Outer Glow / Border
    draw.polygon(shield_pts, fill=(10, 25, 48, 245), outline=(0, 210, 255, 255), width=int(10 * scale))

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
    draw.polygon(inner_pts, fill=(7, 18, 36, 255), outline=(37, 99, 235, 180), width=int(3 * scale))

    # Draw concentric radar arcs
    for radius_factor, width_factor, alpha in [(0.32, 4, 120), (0.24, 3, 160), (0.16, 3, 220)]:
        arc_r = int(sw * radius_factor)
        bbox = [cx - arc_r, cy - arc_r, cx + arc_r, cy + arc_r]
        draw.arc(bbox, start=200, end=340, fill=(0, 210, 255, alpha), width=int(width_factor * scale))
        draw.arc(bbox, start=20, end=160, fill=(0, 210, 255, alpha), width=int(width_factor * scale))

    # Central Traffic Node (Pulsing cyber core)
    core_r = int(sw * 0.08)
    draw.ellipse([cx - core_r, cy - core_r, cx + core_r, cy + core_r], fill=(0, 210, 255, 255), outline=(255, 255, 255, 255), width=int(2 * scale))

    # Traffic In/Out Directional Arrows (Network packets exchanging)
    # Up arrow (upload)
    up_y = cy - int(sw * 0.18)
    draw.polygon([
        (cx, up_y - int(sw * 0.06)),
        (cx - int(sw * 0.05), up_y),
        (cx + int(sw * 0.05), up_y),
    ], fill=(0, 230, 118, 255))
    draw.line([(cx, cy - core_r), (cx, up_y)], fill=(0, 230, 118, 255), width=int(4 * scale))

    # Down arrow (download)
    down_y = cy + int(sw * 0.18)
    draw.polygon([
        (cx, down_y + int(sw * 0.06)),
        (cx - int(sw * 0.05), down_y),
        (cx + int(sw * 0.05), down_y),
    ], fill=(0, 210, 255, 255))
    draw.line([(cx, cy + core_r), (cx, down_y)], fill=(0, 210, 255, 255), width=int(4 * scale))

    # Downsample with high-quality Lanczos filter
    final_img = img.resize(size, Image.Resampling.LANCZOS)
    return final_img


if __name__ == "__main__":
    logo = create_traffic_logo((264, 287))
    logo.save("assets/logos/trafficsentry.png", "PNG")
    # Badge format
    badge = logo.resize((128, 128), Image.Resampling.LANCZOS)
    badge.save("assets/logos/badges/trafficsentry_badge.png", "PNG")
    print("[✔] Successfully created assets/logos/trafficsentry.png and badge!")
