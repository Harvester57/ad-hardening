const fs = require('fs');
const path = require('path');
const puppeteer = require('puppeteer');
const { marked } = require('marked');
const { execSync } = require('child_process');

async function main() {
  const repoRoot = path.resolve(__dirname, '..');
  const mdPath = path.join(repoRoot, 'AD-Hardening-Guidebook.md');
  const pdfPath = path.join(repoRoot, 'AD-Hardening-Guidebook.pdf');
  const cssPath = path.join(repoRoot, 'scripts', 'pdf-style.css');

  console.log("Reading guidebook compiled markdown...");
  if (!fs.existsSync(mdPath)) {
    console.error(`Error: Compiled markdown file not found at ${mdPath}. Run compile_docs.py first.`);
    process.exit(1);
  }

  let mdContent = fs.readFileSync(mdPath, 'utf8');

  // Strip front matter
  if (mdContent.startsWith('---')) {
    const nextThreeDashes = mdContent.indexOf('---', 3);
    if (nextThreeDashes !== -1) {
      mdContent = mdContent.substring(nextThreeDashes + 3);
    }
  }

  console.log("Reading styles...");
  let cssContent = '';
  if (fs.existsSync(cssPath)) {
    cssContent = fs.readFileSync(cssPath, 'utf8');
  } else {
    console.warn(`Warning: Stylesheet not found at ${cssPath}`);
  }

  console.log("Parsing markdown to HTML...");
  const htmlBody = marked(mdContent);

  // Combine into a full HTML document
  const htmlDocument = `<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>Active Directory Hardening Guidebook</title>
  <style>
    ${cssContent}
  </style>
</head>
<body>
  ${htmlBody}
</body>
</html>`;

  // Get commit SHA and Date
  let commitSha = 'unknown';
  try {
    commitSha = execSync('git rev-parse --short HEAD', { cwd: repoRoot }).toString().trim();
  } catch (e) {}
  
  const currentDate = new Date().toLocaleDateString('en-US', {
    month: 'long',
    day: 'numeric',
    year: 'numeric'
  });

  console.log("Launching headless browser...");
  const browser = await puppeteer.launch({
    args: ['--no-sandbox', '--disable-setuid-sandbox', '--disable-gpu']
  });

  try {
    const page = await browser.newPage();
    // Set timeout to 5 minutes (300,000ms) for loading and compiling the large HTML layout
    page.setDefaultTimeout(300000);
    console.log("Loading HTML content...");
    await page.setContent(htmlDocument, { timeout: 300000 });

    console.log("Generating PDF file (this may take a moment)...");
    await page.pdf({
      path: pdfPath,
      format: 'A4',
      margin: {
        top: '25mm',
        bottom: '25mm',
        left: '20mm',
        right: '20mm'
      },
      displayHeaderFooter: true,
      headerTemplate: `
        <div style="font-size: 8px; font-family: 'Inter', sans-serif; width: 100%; text-align: right; padding-right: 20mm; color: #9ca3af;">
          Active Directory Hardening Guidebook
        </div>
      `,
      footerTemplate: `
        <div style="font-size: 8px; font-family: 'Inter', sans-serif; width: 100%; padding-left: 20mm; padding-right: 20mm; display: flex; justify-content: space-between; color: #9ca3af; border-top: 1px solid #e5e7eb; padding-top: 4px; box-sizing: border-box;">
          <span>Commit: ${commitSha} | Generated: ${currentDate}</span>
          <span>Page <span class="pageNumber"></span> of <span class="totalPages"></span></span>
        </div>
      `
    });

    console.log(`PDF successfully generated at: ${pdfPath}`);
  } catch (err) {
    console.error("Error generating PDF:", err);
  } finally {
    await browser.close();
  }
}

main();
