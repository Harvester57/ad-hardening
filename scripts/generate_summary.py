import os
import re

def main():
    repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
    root_readme_path = os.path.join(repo_root, "README.md")
    summary_path = os.path.join(repo_root, "SUMMARY.md")
    
    if not os.path.exists(root_readme_path):
        print(f"Error: {root_readme_path} not found.")
        return

    with open(root_readme_path, "r", encoding="utf-8") as f:
        readme_content = f.read()

    # Parse module directories in order (e.g. 01-architecture, 02-domain-controllers)
    module_matches = re.findall(r'(\d{2}-[a-zA-Z0-9-]+)/README\.md', readme_content)
    modules = []
    for m in module_matches:
        if m not in modules:
            modules.append(m)

    summary_lines = [
        "# Summary",
        "",
        "* [Introduction](README.md)",
        ""
    ]

    for module in modules:
        module_readme = f"{module}/README.md"
        module_readme_abs = os.path.join(repo_root, module_readme)
        
        if os.path.exists(module_readme_abs):
            with open(module_readme_abs, "r", encoding="utf-8") as f:
                content = f.read()
                
            # Parse module title from the first level-1 header
            title_match = re.search(r'^#\s+(.+)$', content, re.MULTILINE)
            module_title = title_match.group(1) if title_match else module
            
            overview_title = module_title
            
            summary_lines.append(f"## {module_title}")
            summary_lines.append(f"* [{overview_title}]({module_readme})")
            
            # Find all local markdown links in the module README
            # e.g. [Link Text](disable-smbv1.md)
            links = re.findall(r'\[([^\]]+)\]\(([^:\n)]+\.md)\)', content)
            
            added_files = set()
            for text, link_path in links:
                if link_path != "README.md" and link_path not in added_files:
                    added_files.add(link_path)
                    # Convert to path relative to repository root
                    rel_path = f"{module}/{link_path}"
                    summary_lines.append(f"    * [{text}]({rel_path})")
        else:
            print(f"Warning: Module README {module_readme} not found.")

    # Add TEMPLATE.md at the end as an Appendix
    template_path = "TEMPLATE.md"
    if os.path.exists(os.path.join(repo_root, template_path)):
        summary_lines.append("")
        summary_lines.append("## Appendix")
        summary_lines.append(f"* [Hardening Template]({template_path})")

    with open(summary_path, 'w', encoding='utf-8') as f:
        f.write('\n'.join(summary_lines) + '\n')
        
    print(f"Successfully generated {summary_path}")

if __name__ == '__main__':
    main()
