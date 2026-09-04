"""Generate JingShield raster favicon assets from the project brand geometry."""

from pathlib import Path

from PIL import Image, ImageDraw


ROOT = Path(__file__).resolve().parents[1]
PUBLIC = ROOT / "web" / "public"
SCALE = 4
CANVAS = 256 * SCALE


def points(values: list[tuple[int, int]]) -> list[tuple[int, int]]:
    return [(x * SCALE, y * SCALE) for x, y in values]


def build_icon() -> Image.Image:
    image = Image.new("RGBA", (CANVAS, CANVAS), (0, 0, 0, 0))
    draw = ImageDraw.Draw(image)
    draw.rounded_rectangle(
        (8 * SCALE, 8 * SCALE, 248 * SCALE, 248 * SCALE),
        radius=58 * SCALE,
        fill="#0A1A2B",
        outline="#43CEE9",
        width=7 * SCALE,
    )
    shield = points([(128, 31), (204, 59), (204, 119), (194, 166), (164, 202), (128, 225), (92, 202), (62, 166), (52, 119), (52, 59), (128, 31)])
    draw.polygon(shield, fill="#071522")
    draw.line(shield, fill="#55DDF5", width=10 * SCALE, joint="curve")

    # Compact whale silhouette: large clean areas remain recognizable at 16px.
    draw.ellipse((82 * SCALE, 102 * SCALE, 174 * SCALE, 166 * SCALE), fill="#46D4F0")
    draw.polygon(points([(83, 121), (55, 105), (64, 135), (49, 151), (89, 147)]), fill="#46D4F0")
    draw.polygon(points([(116, 153), (132, 183), (150, 155)]), fill="#24AFCF")
    draw.ellipse((148 * SCALE, 116 * SCALE, 157 * SCALE, 125 * SCALE), fill="#E7FCFF")
    draw.arc((116 * SCALE, 78 * SCALE, 148 * SCALE, 112 * SCALE), 205, 275, fill="#77E9FF", width=7 * SCALE)
    draw.arc((128 * SCALE, 74 * SCALE, 162 * SCALE, 108 * SCALE), 175, 242, fill="#77E9FF", width=7 * SCALE)
    return image.resize((256, 256), Image.Resampling.LANCZOS)


def main() -> None:
    PUBLIC.mkdir(parents=True, exist_ok=True)
    icon = build_icon()
    icon.save(PUBLIC / "favicon.png", format="PNG", optimize=True)
    icon.save(
        PUBLIC / "favicon.ico",
        format="ICO",
        sizes=[(16, 16), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)],
    )


if __name__ == "__main__":
    main()
