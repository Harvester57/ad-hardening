import os
import re

def main():
    repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
    readme_path = os.path.join(repo_root, 'README.md')
    summary_path = os.path.join(repo_root, 'SUMMARY.md')
    
    if not os.path.exists(readme_path):
        print(f"Error: {readme_path} not found.")
        return

    with open(readme_path, 'r', encoding='utf-8') as f:
        readme_content = f.read()

    summary_lines = [
        "# Summary",
        "",
        "* [Introduction](README.md)",
        ""
    ]

    # Regex to match module header line, e.g.:
    # 1. **[Module 1: Architecture & Administrative Tiering](01-architecture/README.md)**
    module_regex = re.compile(r'^\d+\.\s+\*\*\[(Module\s+\d+:\s+[^\]]+)\]\(([^)]+)\)\*\*')
    
    # Regex to match a hardening control link inside a module list, e.g.:
    #      * [Restrict Tier Logons](01-architecture/restrict-tier-logons.md)
    link_regex = re.compile(r'\[([^\]]+)\]\(([^)]+\.md)\)')

    lines = readme_content.splitlines()
    in_toc = False
    
    for line in lines:
        stripped = line.strip()
        # Find Table of Contents section
        if stripped.startswith('### Table of Contents'):
            in_toc = True
            continue
        # Stop parsing when we hit the Compliance Mapping Matrix or divider
        if in_toc and (stripped.startswith('---') or stripped.startswith('## Compliance Mapping Matrix')):
            in_toc = False
            break
            
        if in_toc:
            module_match = module_regex.match(stripped)
            if module_match:
                module_title = module_match.group(1)
                module_path = module_match.group(2)
                summary_lines.append(f"## {module_title}")
                summary_lines.append(f"* [Overview]({module_path})")
                continue
                
            # If it's a list item and contains a markdown link
            if stripped.startswith('*') or stripped.startswith('-'):
                link_match = link_regex.search(stripped)
                if link_match:
                    title = link_match.group(1)
                    path = link_match.group(2)
                    # Skip module README since we already added it as Overview
                    if not path.endswith('README.md'):
                        summary_lines.append(f"* [{title}]({path})")

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
