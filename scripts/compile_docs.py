import os
import re
from datetime import datetime

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
    
    # We will process line by line to inject header anchors
    lines = content.split('\n')
    header_regex = re.compile(r'^(#+)\s+(.+)$')
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
            
    content = '\n'.join(new_lines)
    
    # Rewrite relative markdown links to HTML anchors: [Text](path.md#anchor)
    # Match links targeting .md files (exclude external, mailto, etc.)
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
            
    # Regex explanation:
    # \[([^\]]+)\] : matches [Link Text]
    # \(([^:#\s)]+\.md) : matches relative link target ending in .md, excluding colons or hash
    # (#[^)]+)? : matches optional anchor segment like #implementation-steps
    # \) : matches closing parenthesis
    md_link_regex = re.compile(r'\[([^\]]+)\]\(([^:#\s)]+\.md)(#[^)]+)?\)')
    content = md_link_regex.sub(link_replacer, content)
    
    # Rewrite internal page anchors (e.g. [Step](#step-1)) to make them unique
    # Match any link starting with '#' where it is not already prefixed with a file ID
    def internal_link_replacer(match):
        text = match.group(1)
        anchor = match.group(2)
        
        # If it's already a full file-level link, leave it
        if anchor.startswith(f'#{file_id}-'):
            return match.group(0)
            
        clean_anchor = slugify(anchor)
        return f'[{text}](#{file_id}-{clean_anchor})'
        
    internal_link_regex = re.compile(r'\[([^\]]+)\]\((#[^)]+)\)')
    content = internal_link_regex.sub(internal_link_replacer, content)
    
    # Rewrite relative image paths: ![alt](images/pic.png)
    def img_replacer(match):
        alt_text = match.group(1)
        img_path = match.group(2)
        
        # Skip external or absolute images
        if img_path.startswith(('http://', 'https://', '/')):
            return match.group(0)
            
        resolved_img = os.path.normpath(os.path.join(file_dir, img_path)).replace('\\', '/')
        return f'![{alt_text}]({resolved_img})'
        
    img_regex = re.compile(r'!\[([^\]]*)\]\(([^:\n)]+)\)')
    content = img_regex.sub(img_replacer, content)
    
    # Convert GitHub alert blockquotes to standard readable strong tags
    # e.g., > [!NOTE] -> > **NOTE:**
    def alert_replacer(match):
        alert_type = match.group(1)
        return f'> **{alert_type}:**'
        
    alert_regex = re.compile(r'^>\s*\[!(NOTE|TIP|IMPORTANT|WARNING|CAUTION)\]', re.MULTILINE | re.IGNORECASE)
    content = alert_regex.sub(alert_replacer, content)
    
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
    
    # Start building compiled markdown
    compiled_lines = []
    
    # 1. Add Cover Page
    current_date = datetime.now().strftime("%B %d, %Y")
    cover_page = f"""<div class="cover-page">

# Active Directory Hardening Guidebook
## Production-Grade Hardening Requirements & Guidelines for Air-Gapped Environments

<hr>

**Standards Alignment:**
- ANSSI (French National Agency for the Security of Information Systems)
- CIS Benchmarks (Center for Internet Security)
- Microsoft Security Baselines

**Target Operating Systems:**
- Domain Controllers: Windows Server 2016 and above
- Tier 2 Client Workstations: Windows 10 and above

<hr>

*Generated dynamically on: {current_date}*

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
            
    # Combine everything and write output
    output_path = os.path.join(repo_root, "AD-Hardening-Guidebook.md")
    with open(output_path, "w", encoding="utf-8") as f:
        f.write('\n'.join(compiled_lines))
        
    print(f"\nCompilation complete! Combined file written to: {output_path}")

if __name__ == "__main__":
    main()
