import os
import re
import sys
import json
import hashlib
import subprocess
from datetime import datetime

def get_git_commit(repo_root):
    try:
        commit = subprocess.check_output(['git', 'rev-parse', '--short', 'HEAD'], cwd=repo_root).decode('utf-8').strip()
        return commit
    except Exception:
        return "unknown"

def get_file_hash(content):
    return hashlib.sha256(content.encode('utf-8')).hexdigest()

def slugify(text):
    # Strip markdown links: [text](url) -> text
    text = re.sub(r'\[([^\]]+)\]\([^)]+\)', r'\1', text)
    # Strip markdown formatting
    text = text.replace('**', '').replace('*', '').replace('`', '')
    # Lowercase
    text = text.lower()
    # Replace non-alphanumeric chars with hyphens
    text = re.sub(r'[^a-z0-9\s_-]', '', text)
    # Replace whitespace/underscores with hyphens
    text = re.sub(r'[\s_]+', '-', text)
    return text.strip('-')

def get_file_id(filepath):
    # Normalizes path to forward slashes and creates a clean unique ID
    normalized = filepath.replace('\\', '/').strip('/')
    # Remove leading dots or slashes
    normalized = re.sub(r'^\.+/', '', normalized)
    # Convert non-alphanumeric chars to hyphens
    file_id = re.sub(r'[^a-zA-Z0-9_-]', '-', normalized)
    return file_id.strip('-')

def process_file_content(content, filepath):
    file_id = get_file_id(filepath)
    file_dir = os.path.dirname(filepath)
    
    # Prepend a target anchor for the top of this file
    processed = f'<div id="{file_id}"></div>\n\n'
    
    # Helper match functions and regexes
    def link_replacer(match):
        text = match.group(1)
        target = match.group(2)
        sub_anchor = match.group(3) or ""
        
        # Skip external links
        if target.startswith(('http://', 'https://', 'mailto:', 'file:')):
            return match.group(0)
            
        # Resolve target path relative to the current file's directory
        resolved_path = os.path.normpath(os.path.join(file_dir, target)).replace('\\', '/')
        target_file_id = get_file_id(resolved_path)
        
        if sub_anchor:
            clean_sub_anchor = slugify(sub_anchor)
            return f'[{text}](#{target_file_id}-{clean_sub_anchor})'
        else:
            return f'[{text}](#{target_file_id})'
            
    md_link_regex = re.compile(r'\[([^\]]+)\]\(([^:#\s)]+\.md)(#[^)]+)?\)')
    
    def internal_link_replacer(match):
        text = match.group(1)
        anchor = match.group(2)
        
        # If it's already a full file-level link, leave it
        if anchor.startswith(f'#{file_id}-'):
            return match.group(0)
            
        clean_anchor = slugify(anchor)
        return f'[{text}](#{file_id}-{clean_anchor})'
        
    internal_link_regex = re.compile(r'\[([^\]]+)\]\((#[^)]+)\)')
    
    def img_replacer(match):
        alt_text = match.group(1)
        img_path = match.group(2)
        
        # Skip external or absolute images
        if img_path.startswith(('http://', 'https://', '/')):
            return match.group(0)
            
        resolved_img = os.path.normpath(os.path.join(file_dir, img_path)).replace('\\', '/')
        return f'![{alt_text}]({resolved_img})'
        
    img_regex = re.compile(r'!\[([^\]]*)\]\(([^:\n)]+)\)')
    
    def alert_replacer(match):
        alert_type = match.group(1)
        return f'> **{alert_type}:**'
        
    alert_regex = re.compile(r'^>\s*\[!(NOTE|TIP|IMPORTANT|WARNING|CAUTION)\]', re.MULTILINE | re.IGNORECASE)
    header_regex = re.compile(r'^(#+)\s+(.+)$')
    
    # Split content by fenced code blocks to avoid modifying anything inside them
    segments = re.split(r'(```[\s\S]*?```)', content)
    
    for i in range(len(segments)):
        if i % 2 == 0:
            segment = segments[i]
            
            # 1. Process line by line to inject header anchors
            lines = segment.split('\n')
            new_lines = []
            for line in lines:
                header_match = header_regex.match(line)
                if header_match:
                    level = header_match.group(1)
                    header_text = header_match.group(2)
                    header_slug = slugify(header_text)
                    anchor = f'<div id="{file_id}-{header_slug}"></div>'
                    new_lines.append(f'{anchor}\n\n{line}')
                else:
                    new_lines.append(line)
            segment = '\n'.join(new_lines)
            
            # 2. Rewrite internal page anchors
            segment = internal_link_regex.sub(internal_link_replacer, segment)
            
            # 3. Rewrite relative markdown links
            segment = md_link_regex.sub(link_replacer, segment)
            
            # 4. Rewrite relative image paths
            segment = img_regex.sub(img_replacer, segment)
            
            # 5. Convert GitHub alert blockquotes
            segment = alert_regex.sub(alert_replacer, segment)
            
            segments[i] = segment
            
    content = ''.join(segments)
    processed += content
    return processed

def get_processed_file(filepath, repo_root, files_cache, new_files_cache, force_all, stats):
    normalized_path = filepath.replace('\\', '/')
    abs_filepath = os.path.join(repo_root, filepath)
    
    if not os.path.exists(abs_filepath):
        print(f"Warning: File {abs_filepath} does not exist.")
        return ""
        
    try:
        mtime = os.path.getmtime(abs_filepath)
    except OSError:
        mtime = 0
        
    cached_entry = files_cache.get(normalized_path)
    if not force_all and cached_entry and cached_entry.get("mtime") == mtime and "processed" in cached_entry:
        new_files_cache[normalized_path] = cached_entry
        stats["skipped"] += 1
        return cached_entry["processed"]
        
    with open(abs_filepath, "r", encoding="utf-8") as f:
        content = f.read()
        
    content_hash = get_file_hash(content)
    if not force_all and cached_entry and cached_entry.get("hash") == content_hash and "processed" in cached_entry:
        cached_entry["mtime"] = mtime
        new_files_cache[normalized_path] = cached_entry
        stats["skipped"] += 1
        return cached_entry["processed"]
        
    stats["processed"] += 1
    processed_content = process_file_content(content, normalized_path)
    new_files_cache[normalized_path] = {
        "hash": content_hash,
        "mtime": mtime,
        "processed": processed_content
    }
    return processed_content

def main():
    repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
    cache_dir = os.path.join(repo_root, ".cache")
    cache_file = os.path.join(cache_dir, "compile_manifest.json")
    
    force_all = "--all" in sys.argv or "--force" in sys.argv or "-f" in sys.argv
    
    manifest = {}
    if not force_all and os.path.exists(cache_file):
        try:
            with open(cache_file, "r", encoding="utf-8") as f:
                manifest = json.load(f)
        except Exception:
            manifest = {}
            
    files_cache = manifest.get("files", {})
    new_files_cache = {}
    stats = {"processed": 0, "skipped": 0}
    
    # Read root README.md to parse module list
    root_readme_path = os.path.join(repo_root, "README.md")
    with open(root_readme_path, "r", encoding="utf-8") as f:
        readme_content = f.read()
        
    module_matches = re.findall(r'(\d{2}-[a-zA-Z0-9-]+)/README\.md', readme_content)
    modules = []
    for m in module_matches:
        if m not in modules:
            modules.append(m)
            
    commit_sha = get_git_commit(repo_root)
    current_date = datetime.now().strftime("%B %d, %Y")

    compiled_lines = []
    
    # 0. Front Matter
    front_matter = f"""---
launch_options:
  args:
    - --no-sandbox
    - --disable-setuid-sandbox
    - --disable-gpu
pdf_options:
  format: A4
  margin:
    top: 25mm
    bottom: 25mm
    left: 20mm
    right: 20mm
  displayHeaderFooter: true
  headerTemplate: |
    <div style="font-size: 8px; font-family: 'Inter', sans-serif; width: 100%; text-align: right; padding-right: 20mm; color: #9ca3af;">
      Active Directory Hardening Guidebook
    </div>
  footerTemplate: |
    <div style="font-size: 8px; font-family: 'Inter', sans-serif; width: 100%; padding-left: 20mm; padding-right: 20mm; display: flex; justify-content: space-between; color: #9ca3af; border-top: 1px solid #e5e7eb; padding-top: 4px;">
      <span>Commit: {commit_sha} | Generated: {current_date}</span>
      <span>Page <span class="pageNumber"></span> of <span class="totalPages"></span></span>
    </div>
---
"""
    compiled_lines.append(front_matter)
    
    # 1. Cover Page
    cover_page = f"""<div class="cover-page">
  <h1>Active Directory Hardening Guidebook</h1>
  <h2>Production-Grade Hardening Requirements & Guidelines for Air-Gapped Environments</h2>
  <hr>
  <p><strong>Standards Alignment:</strong></p>
  <ul>
    <li>ANSSI (French National Agency for the Security of Information Systems)</li>
    <li>CIS Benchmarks (Center for Internet Security)</li>
    <li>Microsoft Security Baselines</li>
  </ul>
  <p><strong>Target Operating Systems:</strong></p>
  <ul>
    <li>Domain Controllers: Windows Server 2016 and above</li>
    <li>Tier 2 Client Workstations: Windows 10 and above</li>
  </ul>
  <hr>
  <p><em>Generated dynamically on: {current_date}</em></p>
</div>
"""
    compiled_lines.append(cover_page)
    
    # 2. Root README.md
    processed_readme = get_processed_file("README.md", repo_root, files_cache, new_files_cache, force_all, stats)
    compiled_lines.append(processed_readme)
    
    # 3. Modules
    for module in modules:
        module_readme = f"{module}/README.md"
        module_readme_abs = os.path.join(repo_root, module_readme)
        if os.path.exists(module_readme_abs):
            with open(module_readme_abs, "r", encoding="utf-8") as f:
                module_readme_content = f.read()
                
            module_files_matches = re.findall(r'\[[^\]]+\]\(([^:\n)]+\.md)\)', module_readme_content)
            module_files = []
            for f_match in module_files_matches:
                if f_match != "README.md" and f_match not in module_files:
                    module_files.append(f_match)
                    
            compiled_lines.append('\n<div style="page-break-before: always;"></div>\n')
            processed_mod_readme = get_processed_file(module_readme, repo_root, files_cache, new_files_cache, force_all, stats)
            compiled_lines.append(processed_mod_readme)
            
            for file_name in module_files:
                file_rel_path = f"{module}/{file_name}"
                compiled_lines.append('\n<div style="page-break-before: always;"></div>\n')
                processed_file_content = get_processed_file(file_rel_path, repo_root, files_cache, new_files_cache, force_all, stats)
                compiled_lines.append(processed_file_content)
        else:
            print(f"Warning: Module README {module_readme} not found.")
            
    # 3.5. Implementation Roadmap
    roadmap_file = "roadmap/implementation-plan.md"
    if os.path.exists(os.path.join(repo_root, roadmap_file)):
        compiled_lines.append('\n<div style="page-break-before: always;"></div>\n')
        processed_roadmap = get_processed_file(roadmap_file, repo_root, files_cache, new_files_cache, force_all, stats)
        compiled_lines.append(processed_roadmap)
        
    # 4. Compliance Matrices
    compliance_files = [
        "compliance/anssi.md",
        "compliance/cis.md",
        "compliance/microsoft.md"
    ]
    for comp_file in compliance_files:
        if os.path.exists(os.path.join(repo_root, comp_file)):
            compiled_lines.append('\n<div style="page-break-before: always;"></div>\n')
            processed_comp = get_processed_file(comp_file, repo_root, files_cache, new_files_cache, force_all, stats)
            compiled_lines.append(processed_comp)
            
    # Save cache
    os.makedirs(cache_dir, exist_ok=True)
    with open(cache_file, "w", encoding="utf-8") as f:
        json.dump({"version": 1, "files": new_files_cache}, f)
        
    final_content = '\n'.join(compiled_lines)
    output_path = os.path.join(repo_root, "AD-Hardening-Guidebook.md")
    
    # Check if output is unchanged before overwriting
    if os.path.exists(output_path):
        with open(output_path, "r", encoding="utf-8") as f:
            existing_content = f.read()
        if existing_content == final_content:
            print(f"Compilation up-to-date: 0 processed, {stats['skipped']} skipped (cached). Guidebook output unchanged.")
            return
            
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(final_content)
        
    print(f"Compilation complete: {stats['processed']} processed, {stats['skipped']} skipped. Output written to: {output_path}")

if __name__ == "__main__":
    main()
