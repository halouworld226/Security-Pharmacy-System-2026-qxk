"""图形验证码生成工具"""
import random
import string
import io
from PIL import Image, ImageDraw, ImageFont


def generate_captcha_text(length=4):
    """生成随机验证码文字（排除易混淆字符 0/O/1/I/l）"""
    chars = '23456789ABCDEFGHJKMNPQRSTUVWXYZ'
    return ''.join(random.choices(chars, k=length))


def generate_captcha_image(text):
    """生成带干扰的验证码图片，返回 PNG 字节流"""
    width, height = 130, 48

    # 随机背景色
    bg = (random.randint(220, 255), random.randint(220, 255), random.randint(220, 255))
    img = Image.new('RGB', (width, height), bg)
    draw = ImageDraw.Draw(img)

    # 干扰点
    for _ in range(80):
        x, y = random.randint(0, width - 1), random.randint(0, height - 1)
        draw.point((x, y), fill=(random.randint(0, 180), random.randint(0, 180), random.randint(0, 180)))

    # 干扰线
    for _ in range(3):
        x1, y1 = random.randint(0, width // 2), random.randint(0, height)
        x2, y2 = random.randint(width // 2, width), random.randint(0, height)
        draw.line([(x1, y1), (x2, y2)], fill=(150, 150, 150), width=1)

    # 绘制文字
    try:
        font = ImageFont.truetype('C:/Windows/Fonts/arial.ttf', 30)
    except Exception:
        try:
            font = ImageFont.truetype('arial.ttf', 30)
        except Exception:
            font = ImageFont.load_default()

    for i, ch in enumerate(text):
        x = 10 + i * 28 + random.randint(-4, 4)
        y = random.randint(5, 14)
        color = (random.randint(0, 80), random.randint(0, 80), random.randint(0, 80))
        draw.text((x, y), ch, font=font, fill=color)

    buf = io.BytesIO()
    img.save(buf, 'PNG')
    buf.seek(0)
    return buf
