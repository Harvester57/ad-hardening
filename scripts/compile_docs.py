import os
import re
import subprocess
from datetime import datetime

def get_git_commit(repo_root):
    try:
        commit = subprocess.check_output(['git', 'rev-parse', '--short', 'HEAD'], cwd=repo_root).decode('utf-8').strip()
        return commit
    except Exception:
        return "unknown"


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

def process_file(filepath, repo_root):
    file_id = get_file_id(filepath)
    file_dir = os.path.dirname(filepath)
    abs_filepath = os.path.join(repo_root, filepath)
    
    if not os.path.exists(abs_filepath):
        print(f"Warning: File {abs_filepath} does not exist.")
        return ""
        
    with open(abs_filepath, "r", encoding="utf-8") as f:
        content = f.read()
        
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
            # Sub-anchors look like "#implementation-steps", slugify the anchor text
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
        # If the index is even, it's normal markdown text (not inside a code block)
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
                    # Prepend an HTML anchor for header cross-referencing
                    anchor = f'<div id="{file_id}-{header_slug}"></div>'
                    new_lines.append(f'{anchor}\n{line}')
                else:
                    new_lines.append(line)
            segment = '\n'.join(new_lines)
            
            # 2. Rewrite internal page anchors (e.g. [Step](#step-1)) to make them unique
            segment = internal_link_regex.sub(internal_link_replacer, segment)
            
            # 3. Rewrite relative markdown links to HTML anchors: [Text](path.md#anchor)
            segment = md_link_regex.sub(link_replacer, segment)
            
            # 4. Rewrite relative image paths: ![alt](images/pic.png)
            segment = img_regex.sub(img_replacer, segment)
            
            # 5. Convert GitHub alert blockquotes to standard readable strong tags
            segment = alert_regex.sub(alert_replacer, segment)
            
            segments[i] = segment
            
    content = ''.join(segments)
    processed += content
    return processed

def main():
    repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
    
    # Read root README.md to parse module list
    root_readme_path = os.path.join(repo_root, "README.md")
    with open(root_readme_path, "r", encoding="utf-8") as f:
        readme_content = f.read()
        
    # Parse module directories in order (e.g. 01-architecture, 02-domain-controllers)
    module_matches = re.findall(r'(\d{2}-[a-zA-Z0-9-]+)/README\.md', readme_content)
    modules = []
    for m in module_matches:
        if m not in modules:
            modules.append(m)
            
    print(f"Discovered {len(modules)} modules in order: {modules}")
    
    # Get git commit hash
    commit_sha = get_git_commit(repo_root)
    current_date = datetime.now().strftime("%B %d, %Y")

    # Start building compiled markdown
    compiled_lines = []
    
    # 0. Add Front Matter for md-to-pdf configuration
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
    
    # 1. Add Cover Page in HTML format to prevent it from interfering with Markdown parsing
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
    
    # 2. Add root README.md content (Introduction & Compliance Mapping Matrix)
    print("Processing root README.md...")
    processed_readme = process_file("README.md", repo_root)
    compiled_lines.append(processed_readme)
    
    # 3. Add modules and their respective files
    for module in modules:
        print(f"Processing module: {module}...")
        module_readme = f"{module}/README.md"
        
        # Read module README to find files listed inside it
        module_readme_abs = os.path.join(repo_root, module_readme)
        if os.path.exists(module_readme_abs):
            with open(module_readme_abs, "r", encoding="utf-8") as f:
                module_readme_content = f.read()
                
            # Find all local markdown links in the module README
            # e.g. [Link](disable-smbv1.md)
            module_files_matches = re.findall(r'\[[^\]]+\]\(([^:\n)]+\.md)\)', module_readme_content)
            module_files = []
            for f_match in module_files_matches:
                if f_match != "README.md" and f_match not in module_files:
                    module_files.append(f_match)
                    
            # Page break before each module README
            compiled_lines.append('\n<div style="page-break-before: always;"></div>\n')
            
            # Process module README
            processed_mod_readme = process_file(module_readme, repo_root)
            compiled_lines.append(processed_mod_readme)
            
            # Process files in the module
            for file_name in module_files:
                file_rel_path = f"{module}/{file_name}"
                print(f"  -> File: {file_rel_path}")
                
                # Page break before each hardening file
                compiled_lines.append('\n<div style="page-break-before: always;"></div>\n')
                
                processed_file_content = process_file(file_rel_path, repo_root)
                compiled_lines.append(processed_file_content)
        else:
            print(f"Warning: Module README {module_readme} not found.")
            
    # 4. Add Compliance Matrices
    compliance_files = [
        "compliance/anssi.md",
        "compliance/cis.md",
        "compliance/microsoft.md"
    ]
    for comp_file in compliance_files:
        comp_file_abs = os.path.join(repo_root, comp_file)
        if os.path.exists(comp_file_abs):
            print(f"Processing compliance file: {comp_file}...")
            # Page break before each compliance matrix
            compiled_lines.append('\n<div style="page-break-before: always;"></div>\n')
            processed_comp = process_file(comp_file, repo_root)
            compiled_lines.append(processed_comp)
        else:
            print(f"Warning: Compliance file {comp_file} not found.")
            
    # Combine everything and write output
    output_path = os.path.join(repo_root, "AD-Hardening-Guidebook.md")
    with open(output_path, "w", encoding="utf-8") as f:
        f.write('\n'.join(compiled_lines))
        
    print(f"\nCompilation complete! Combined file written to: {output_path}")

if __name__ == "__main__":
    main()
