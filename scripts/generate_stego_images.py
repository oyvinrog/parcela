#!/usr/bin/env python3
"""
Generate simple 32x32 PNG icons for Parcela steganography.
Each icon is a simple recognizable symbol with minimal file size.
"""

import struct
import zlib
import os

def create_png(width, height, pixels):
    """Create a minimal PNG from RGBA pixel data."""
    def png_chunk(chunk_type, data):
        chunk_len = struct.pack('>I', len(data))
        chunk_crc = struct.pack('>I', zlib.crc32(chunk_type + data) & 0xffffffff)
        return chunk_len + chunk_type + data + chunk_crc
    
    # PNG signature
    signature = b'\x89PNG\r\n\x1a\n'
    
    # IHDR chunk
    ihdr_data = struct.pack('>IIBBBBB', width, height, 8, 6, 0, 0, 0)  # 8-bit RGBA
    ihdr = png_chunk(b'IHDR', ihdr_data)
    
    # IDAT chunk (image data)
    raw_data = b''
    for y in range(height):
        raw_data += b'\x00'  # Filter type: None
        for x in range(width):
            idx = (y * width + x) * 4
            raw_data += bytes(pixels[idx:idx+4])
    
    compressed = zlib.compress(raw_data, 9)
    idat = png_chunk(b'IDAT', compressed)
    
    # IEND chunk
    iend = png_chunk(b'IEND', b'')
    
    return signature + ihdr + idat + iend

def create_image(width, height, draw_func):
    """Create an image using a drawing function."""
    pixels = [0, 0, 0, 0] * (width * height)  # Transparent background
    
    def set_pixel(x, y, r, g, b, a=255):
        if 0 <= x < width and 0 <= y < height:
            idx = (y * width + x) * 4
            pixels[idx] = r
            pixels[idx + 1] = g
            pixels[idx + 2] = b
            pixels[idx + 3] = a
    
    def fill_circle(cx, cy, radius, r, g, b, a=255):
        for y in range(height):
            for x in range(width):
                dx, dy = x - cx, y - cy
                if dx*dx + dy*dy <= radius*radius:
                    set_pixel(x, y, r, g, b, a)
    
    def draw_circle(cx, cy, radius, r, g, b, thickness=2, a=255):
        for y in range(height):
            for x in range(width):
                dx, dy = x - cx, y - cy
                dist = (dx*dx + dy*dy) ** 0.5
                if abs(dist - radius) <= thickness / 2:
                    set_pixel(x, y, r, g, b, a)
    
    def fill_rect(x1, y1, x2, y2, r, g, b, a=255):
        for y in range(y1, y2+1):
            for x in range(x1, x2+1):
                set_pixel(x, y, r, g, b, a)
    
    def draw_line(x1, y1, x2, y2, r, g, b, thickness=2, a=255):
        steps = max(abs(x2-x1), abs(y2-y1), 1)
        for i in range(steps + 1):
            t = i / steps
            x = int(x1 + (x2 - x1) * t)
            y = int(y1 + (y2 - y1) * t)
            for dx in range(-thickness//2, thickness//2 + 1):
                for dy in range(-thickness//2, thickness//2 + 1):
                    set_pixel(x + dx, y + dy, r, g, b, a)
    
    draw_func(set_pixel, fill_circle, draw_circle, fill_rect, draw_line)
    return pixels

# Define all 20 icons
def draw_smiley(set_pixel, fill_circle, draw_circle, fill_rect, draw_line):
    # Yellow face
    fill_circle(16, 16, 14, 255, 220, 0)
    # Eyes
    fill_circle(11, 12, 2, 0, 0, 0)
    fill_circle(21, 12, 2, 0, 0, 0)
    # Smile (arc approximation)
    for x in range(9, 24):
        y = 20 + int(((x - 16) ** 2) / 20)
        set_pixel(x, y, 0, 0, 0)
        set_pixel(x, y+1, 0, 0, 0)

def draw_sun(set_pixel, fill_circle, draw_circle, fill_rect, draw_line):
    # Sun body
    fill_circle(16, 16, 8, 255, 200, 0)
    # Rays
    for angle in range(0, 360, 45):
        import math
        rad = math.radians(angle)
        x1 = int(16 + 10 * math.cos(rad))
        y1 = int(16 + 10 * math.sin(rad))
        x2 = int(16 + 14 * math.cos(rad))
        y2 = int(16 + 14 * math.sin(rad))
        draw_line(x1, y1, x2, y2, 255, 180, 0, 2)

def draw_star(set_pixel, fill_circle, draw_circle, fill_rect, draw_line):
    import math
    cx, cy = 16, 16
    outer_r, inner_r = 13, 5
    for i in range(5):
        # Outer point
        angle1 = math.radians(-90 + i * 72)
        x1 = int(cx + outer_r * math.cos(angle1))
        y1 = int(cy + outer_r * math.sin(angle1))
        # Inner point
        angle2 = math.radians(-90 + i * 72 + 36)
        x2 = int(cx + inner_r * math.cos(angle2))
        y2 = int(cy + inner_r * math.sin(angle2))
        # Next outer point
        angle3 = math.radians(-90 + (i + 1) * 72)
        x3 = int(cx + outer_r * math.cos(angle3))
        y3 = int(cy + outer_r * math.sin(angle3))
        draw_line(x1, y1, x2, y2, 255, 215, 0, 2)
        draw_line(x2, y2, x3, y3, 255, 215, 0, 2)

def draw_heart(set_pixel, fill_circle, draw_circle, fill_rect, draw_line):
    fill_circle(11, 12, 6, 220, 20, 60)
    fill_circle(21, 12, 6, 220, 20, 60)
    # Triangle bottom
    for y in range(12, 28):
        half_width = max(0, 12 - (y - 12) * 12 // 16)
        for x in range(16 - half_width, 16 + half_width + 1):
            set_pixel(x, y, 220, 20, 60)

def draw_moon(set_pixel, fill_circle, draw_circle, fill_rect, draw_line):
    fill_circle(16, 16, 12, 255, 255, 200)
    fill_circle(22, 12, 10, 0, 0, 0, 0)  # Transparent cutout

def draw_cloud(set_pixel, fill_circle, draw_circle, fill_rect, draw_line):
    fill_circle(12, 18, 7, 200, 200, 220)
    fill_circle(20, 16, 8, 200, 200, 220)
    fill_circle(26, 19, 5, 200, 200, 220)
    fill_rect(10, 18, 27, 24, 200, 200, 220)

def draw_flower(set_pixel, fill_circle, draw_circle, fill_rect, draw_line):
    # Petals
    import math
    for i in range(6):
        angle = math.radians(i * 60)
        px = int(16 + 8 * math.cos(angle))
        py = int(14 + 8 * math.sin(angle))
        fill_circle(px, py, 5, 255, 100, 150)
    # Center
    fill_circle(16, 14, 4, 255, 220, 0)
    # Stem
    draw_line(16, 18, 16, 30, 50, 180, 50, 2)

def draw_tree(set_pixel, fill_circle, draw_circle, fill_rect, draw_line):
    # Trunk
    fill_rect(14, 20, 18, 30, 139, 90, 43)
    # Foliage
    fill_circle(16, 12, 10, 34, 139, 34)

def draw_house(set_pixel, fill_circle, draw_circle, fill_rect, draw_line):
    # Roof
    for y in range(6, 16):
        half_width = y - 6
        for x in range(16 - half_width, 16 + half_width + 1):
            set_pixel(x, y, 180, 60, 60)
    # Body
    fill_rect(8, 16, 24, 28, 200, 180, 140)
    # Door
    fill_rect(14, 20, 18, 28, 139, 90, 43)
    # Window
    fill_rect(20, 19, 23, 23, 135, 206, 250)

def draw_key(set_pixel, fill_circle, draw_circle, fill_rect, draw_line):
    draw_circle(10, 12, 5, 255, 215, 0, 2)
    draw_line(14, 12, 28, 12, 255, 215, 0, 2)
    draw_line(24, 12, 24, 17, 255, 215, 0, 2)
    draw_line(28, 12, 28, 17, 255, 215, 0, 2)

def draw_lock(set_pixel, fill_circle, draw_circle, fill_rect, draw_line):
    # Shackle
    draw_circle(16, 10, 6, 128, 128, 128, 3)
    fill_rect(8, 10, 12, 16, 0, 0, 0, 0)
    fill_rect(20, 10, 24, 16, 0, 0, 0, 0)
    # Body
    fill_rect(8, 14, 24, 28, 255, 200, 0)
    fill_circle(16, 20, 2, 0, 0, 0)

def draw_shield(set_pixel, fill_circle, draw_circle, fill_rect, draw_line):
    for y in range(4, 28):
        if y < 18:
            half_width = 10
        else:
            half_width = max(0, 10 - (y - 18))
        for x in range(16 - half_width, 16 + half_width + 1):
            set_pixel(x, y, 65, 105, 225)
    # Cross
    fill_rect(14, 8, 18, 24, 255, 255, 255)
    fill_rect(10, 12, 22, 16, 255, 255, 255)

def draw_diamond(set_pixel, fill_circle, draw_circle, fill_rect, draw_line):
    cx, cy = 16, 16
    for y in range(4, 29):
        if y <= 16:
            half_width = y - 4
        else:
            half_width = 28 - y
        for x in range(cx - half_width, cx + half_width + 1):
            set_pixel(x, y, 135, 206, 250)
    # Facets
    draw_line(16, 4, 4, 16, 200, 230, 255, 1)
    draw_line(16, 4, 28, 16, 200, 230, 255, 1)

def draw_crown(set_pixel, fill_circle, draw_circle, fill_rect, draw_line):
    fill_rect(6, 18, 26, 26, 255, 215, 0)
    # Points
    for px in [8, 16, 24]:
        for y in range(8, 19):
            half = (18 - y) // 3
            for x in range(px - half, px + half + 1):
                set_pixel(x, y, 255, 215, 0)
    # Jewels
    fill_circle(8, 22, 2, 220, 20, 60)
    fill_circle(16, 22, 2, 30, 144, 255)
    fill_circle(24, 22, 2, 50, 205, 50)

def draw_bird(set_pixel, fill_circle, draw_circle, fill_rect, draw_line):
    fill_circle(20, 14, 6, 100, 149, 237)
    fill_circle(12, 16, 8, 100, 149, 237)
    # Beak
    fill_rect(26, 13, 30, 15, 255, 165, 0)
    # Eye
    fill_circle(24, 12, 1, 0, 0, 0)
    # Wing
    fill_circle(10, 18, 4, 70, 130, 180)

def draw_fish(set_pixel, fill_circle, draw_circle, fill_rect, draw_line):
    # Body (oval approximation)
    for y in range(10, 23):
        cy = 16
        half = int(((1 - ((y - cy) / 6) ** 2) ** 0.5) * 12) if abs(y - cy) <= 6 else 0
        for x in range(14 - half, 14 + half + 1):
            set_pixel(x, y, 255, 165, 0)
    # Tail
    for y in range(10, 23):
        half = abs(y - 16) // 2 + 1
        for x in range(26 - half, 28):
            set_pixel(x, y, 255, 140, 0)
    # Eye
    fill_circle(8, 15, 2, 0, 0, 0)

def draw_mountain(set_pixel, fill_circle, draw_circle, fill_rect, draw_line):
    # Main mountain
    for y in range(6, 28):
        half_width = (y - 6) * 12 // 22
        for x in range(16 - half_width, 16 + half_width + 1):
            set_pixel(x, y, 100, 100, 100)
    # Snow cap
    for y in range(6, 14):
        half_width = (y - 6) * 5 // 8
        for x in range(16 - half_width, 16 + half_width + 1):
            set_pixel(x, y, 255, 255, 255)

def draw_wave(set_pixel, fill_circle, draw_circle, fill_rect, draw_line):
    import math
    for x in range(32):
        base_y = 16 + int(4 * math.sin(x * 0.4))
        for y in range(base_y, 28):
            alpha = 255 - (y - base_y) * 20
            set_pixel(x, y, 30, 144, 255, max(100, alpha))

def draw_flame(set_pixel, fill_circle, draw_circle, fill_rect, draw_line):
    # Outer flame (orange)
    for y in range(4, 28):
        if y < 16:
            half = (y - 4) * 6 // 12
        else:
            half = max(1, 6 - (y - 16) * 6 // 12)
        for x in range(16 - half, 16 + half + 1):
            set_pixel(x, y, 255, 100, 0)
    # Inner flame (yellow)
    for y in range(10, 26):
        if y < 18:
            half = (y - 10) * 3 // 8
        else:
            half = max(0, 3 - (y - 18) * 3 // 8)
        for x in range(16 - half, 16 + half + 1):
            set_pixel(x, y, 255, 220, 0)

def draw_snowflake(set_pixel, fill_circle, draw_circle, fill_rect, draw_line):
    import math
    cx, cy = 16, 16
    for i in range(6):
        angle = math.radians(i * 60)
        x2 = int(cx + 12 * math.cos(angle))
        y2 = int(cy + 12 * math.sin(angle))
        draw_line(cx, cy, x2, y2, 135, 206, 250, 2)
        # Small branches
        for t in [0.5, 0.75]:
            bx = int(cx + 12 * t * math.cos(angle))
            by = int(cy + 12 * t * math.sin(angle))
            for da in [-30, 30]:
                ba = angle + math.radians(da)
                bx2 = int(bx + 4 * math.cos(ba))
                by2 = int(by + 4 * math.sin(ba))
                draw_line(bx, by, bx2, by2, 135, 206, 250, 1)

# Generate all icons
icons = [
    ("smiley", draw_smiley),
    ("sun", draw_sun),
    ("star", draw_star),
    ("heart", draw_heart),
    ("moon", draw_moon),
    ("cloud", draw_cloud),
    ("flower", draw_flower),
    ("tree", draw_tree),
    ("house", draw_house),
    ("key", draw_key),
    ("lock", draw_lock),
    ("shield", draw_shield),
    ("diamond", draw_diamond),
    ("crown", draw_crown),
    ("bird", draw_bird),
    ("fish", draw_fish),
    ("mountain", draw_mountain),
    ("wave", draw_wave),
    ("flame", draw_flame),
    ("snowflake", draw_snowflake),
]

if __name__ == "__main__":
    script_dir = os.path.dirname(os.path.abspath(__file__))
    output_dir = os.path.join(script_dir, "..", "assets", "stego")
    os.makedirs(output_dir, exist_ok=True)
    
    for name, draw_func in icons:
        pixels = create_image(32, 32, draw_func)
        png_data = create_png(32, 32, pixels)
        output_path = os.path.join(output_dir, f"{name}.png")
        with open(output_path, 'wb') as f:
            f.write(png_data)
        print(f"Generated {name}.png ({len(png_data)} bytes)")
    
    print(f"\nGenerated {len(icons)} icons in {output_dir}")
