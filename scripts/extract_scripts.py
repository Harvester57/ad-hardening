import os
import re

def main():
    repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
    modules = [
        "01-architecture",
        "02-domain-controllers",
        "03-identities-services",
        "04-network-firewall",
        "05-logging-monitoring",
        "06-operations-maintenance",
        "07-paws",
        "08-endpoints"
    ]
    
    # Regex to match code blocks of type powershell or ps1
    code_block_pattern = re.compile(r'(```(?:powershell|ps1)\r?\n(.*?)\r?\n```)', re.DOTALL)
    
    total_extracted = 0
    total_linked = 0
    
    for module in modules:
        module_path = os.path.join(repo_root, module)
        if not os.path.exists(module_path):
            continue
            
        impl_dir = os.path.join(module_path, "implementation_scripts")
        audit_dir = os.path.join(module_path, "audit_scripts")
        
        for file in sorted(os.listdir(module_path)):
            if not file.endswith(".md") or file.lower() == "readme.md":
                continue
                
            file_path = os.path.join(module_path, file)
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read()
                
            matches = code_block_pattern.findall(content)
            if not matches:
                continue
                
            modified = False
            for full_block, code_content in matches:
                code_lines = code_content.strip().split("\n")
                if not code_lines:
                    continue
                first_line = code_lines[0].strip()
                
                # Match comments like '# Name.ps1'
                filename_match = re.match(r'^#\s*([a-zA-Z0-9_-]+\.ps1)', first_line, re.IGNORECASE)
                if not filename_match:
                    continue
                    
                filename = filename_match.group(1)
                
                # Classify implementation vs audit
                lower_name = filename.lower()
                is_audit = (
                    lower_name.startswith("audit-") or
                    lower_name.startswith("test-") or
                    lower_name.startswith("get-") or
                    lower_name.startswith("check-")
                )
                
                folder_name = "audit_scripts" if is_audit else "implementation_scripts"
                target_dir = audit_dir if is_audit else impl_dir
                
                # Ensure the target directory exists
                os.makedirs(target_dir, exist_ok=True)
                
                # Write the script content to the target file
                script_path = os.path.join(target_dir, filename)
                # Normalize line endings to Windows style CRLF (since this repository runs on Windows)
                normalized_code = code_content.replace('\r\n', '\n').replace('\n', '\r\n')
                with open(script_path, "w", encoding="utf-8", newline="") as sf:
                    sf.write(normalized_code + "\r\n")
                total_extracted += 1
                
                # Check if download link is already present in the markdown file
                link_text = f"[Download Script: {filename}]({folder_name}/{filename})"
                if link_text not in content:
                    # Insert the download link right before the code block
                    new_block = f"{link_text}\n\n{full_block}"
                    content = content.replace(full_block, new_block, 1)
                    modified = True
                    total_linked += 1
                    
            if modified:
                with open(file_path, "w", encoding="utf-8") as f:
                    f.write(content)
                    
    print(f"Extraction complete! Extracted {total_extracted} scripts and added {total_linked} links.")

if __name__ == "__main__":
    main()
