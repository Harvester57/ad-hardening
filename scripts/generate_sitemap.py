import argparse
import os
import re
import subprocess
import sys
from urllib.parse import quote
from xml.sax.saxutils import escape

DEFAULT_SITE_URL = "https://ad.harvester.fr"

SITEMAP_TEMPLATE = """<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
{urls}</urlset>
"""

URL_TEMPLATE = """  <url>
    <loc>{loc}</loc>
{lastmod}  </url>
"""


def parse_summary(summary_path):
    """Extract ordered local page paths from SUMMARY.md, ignoring anchors and external links."""
    pages = []
    seen = set()

    with open(summary_path, "r", encoding="utf-8") as f:
        content = f.read()

    for _, link in re.findall(r'\[([^\]]+)\]\(([^)]+)\)', content):
        if link.startswith(("#", "http://", "https://", "mailto:")):
            continue
        path = link.split("#")[0].strip()
        if not path.endswith(".md") or path == "":
            continue
        if path not in seen:
            seen.add(path)
            pages.append(path)

    return pages


def git_lastmod(repo_root, path):
    """Return the ISO 8601 commit date of the last change to a file, or None when unavailable."""
    try:
        result = subprocess.run(
            ["git", "log", "-1", "--format=%cI", "--", path],
            cwd=repo_root,
            capture_output=True,
            text=True,
            check=True
        )
    except (subprocess.CalledProcessError, OSError):
        return None

    lastmod = result.stdout.strip()
    return lastmod if lastmod else None


def page_url(site_url, page_path):
    """Map a markdown source path to the generated HTML URL."""
    html_path = page_path[:-len(".md")] + ".html"
    return site_url.rstrip("/") + "/" + quote(html_path, safe="/")


def generate_sitemap(pages, repo_root, site_url, build_dir):
    urls_xml = []
    missing = []
    lastmod_warned = False

    for page_path in pages:
        loc = page_url(site_url, page_path)

        html_path = os.path.join(build_dir, page_path[:-len(".md")] + ".html")
        if not os.path.exists(html_path):
            missing.append(page_path)

        lastmod = git_lastmod(repo_root, page_path)
        if lastmod:
            lastmod_xml = f"    <lastmod>{lastmod}</lastmod>\n"
        else:
            lastmod_xml = ""
            if not lastmod_warned:
                print("Warning: git history unavailable, <lastmod> entries omitted.")
                lastmod_warned = True

        urls_xml.append(URL_TEMPLATE.format(loc=escape(loc), lastmod=lastmod_xml))

    return SITEMAP_TEMPLATE.format(urls="".join(urls_xml)), missing


def main():
    repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
    default_summary = os.path.join(repo_root, "SUMMARY.md")
    default_build = os.path.join(repo_root, "_book")

    parser = argparse.ArgumentParser(
        description="Generate sitemap.xml and robots.txt from SUMMARY.md after the GitBook build."
    )
    parser.add_argument("--site-url", default=DEFAULT_SITE_URL,
                        help="Base URL of the deployed site (default: %(default)s)")
    parser.add_argument("--summary", default=default_summary,
                        help="Path to SUMMARY.md (default: %(default)s)")
    parser.add_argument("--build-dir", default=default_build,
                        help="HonKit build output directory (default: %(default)s)")
    parser.add_argument("--output-dir", default=None,
                        help="Directory to write sitemap.xml and robots.txt "
                             "(default: the build directory)")
    args = parser.parse_args()

    if not os.path.exists(args.summary):
        print(f"Error: {args.summary} not found.")
        sys.exit(1)

    if args.output_dir is None:
        args.output_dir = args.build_dir

    os.makedirs(args.output_dir, exist_ok=True)

    pages = parse_summary(args.summary)
    if not pages:
        print("Error: no pages found in SUMMARY.md.")
        sys.exit(1)

    sitemap_xml, missing = generate_sitemap(pages, repo_root, args.site_url, args.build_dir)

    sitemap_path = os.path.join(args.output_dir, "sitemap.xml")
    with open(sitemap_path, "w", encoding="utf-8") as f:
        f.write(sitemap_xml)

    site_url = args.site_url.rstrip("/") + "/"
    robots_path = os.path.join(args.output_dir, "robots.txt")
    with open(robots_path, "w", encoding="utf-8") as f:
        f.write("User-agent: *\n")
        f.write("Allow: /\n")
        f.write("\n")
        f.write(f"Sitemap: {site_url}sitemap.xml\n")

    print(f"Generated {sitemap_path} ({len(pages)} pages)")
    print(f"Generated {robots_path}")

    if missing:
        print("Warning: pages present in SUMMARY.md but missing from the build output:")
        for page_path in missing:
            print(f"  - {page_path}")
        sys.exit(1)


if __name__ == '__main__':
    main()
