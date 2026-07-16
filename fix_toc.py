from docx import Document
from docx.oxml.ns import qn
import os, shutil, tempfile

src = r'D:\python-my-project\计安大作业\计算机安全报告.docx'

tmpdir = tempfile.mkdtemp()
tmp_src = os.path.join(tmpdir, 'source.docx')
shutil.copy2(src, tmp_src)

doc = Document(tmp_src)

for i, p in enumerate(doc.paragraphs):
    parts = []
    for run in p.runs:
        for child in run._element.iter():
            if child.tag.endswith('}instrText') and child.text:
                parts.append((child, child.text))

    if not parts:
        continue

    combined = ''.join(text for _, text in parts)
    old_combined = combined
    combined = combined.replace('\\o "3-3"', '\\o "1-3"')
    combined = combined.replace('\\t "' + chr(26631) + chr(39064) + ' 1,1"', '')

    if combined == old_combined:
        continue

    print(f'Paragraph {i}: Updated TOC field code')
    print(f'  Old: {repr(old_combined)}')
    print(f'  New: {repr(combined)}')

    first = True
    for child, _ in parts:
        child.text = combined if first else ''
        first = False

tmp_out = os.path.join(tmpdir, 'output.docx')
doc.save(tmp_out)

final = r'D:\python-my-project\计安大作业\代码\计算机安全报告_已修复目录.docx'
if os.path.exists(final):
    os.remove(final)
shutil.copy2(tmp_out, final)

shutil.rmtree(tmpdir)
print(f'\nSaved to {final}')
