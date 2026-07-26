#!/usr/bin/env bash
#
# Rebuild the CSS and JS inlined into index.html.
#
# The landing page has no third-party runtime dependency. It used to load the
# Tailwind Play CDN and Prism from cdnjs with no subresource integrity, which
# meant the public face of a supply-chain governance tool executed unverified
# third-party code on every visit. Styles and highlighting are now built here
# and pasted into the page.
#
# Run this after changing markup, so newly used Tailwind classes are emitted.
#
#   bash scripts/build_landing_assets.sh
#
# Requires node and npm. Writes nothing outside a temporary directory; it
# prints the two blocks to paste, and tells you where they go.

set -euo pipefail

TAILWIND_VERSION="3.4.17"
PRISM_VERSION="1.30.0"

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
build_dir="$(mktemp -d)"
trap 'rm -rf "$build_dir"' EXIT

command -v npm >/dev/null || {
  echo "npm is required to rebuild the landing assets." >&2
  exit 1
}

cp "${repo_root}/index.html" "${build_dir}/index.html"
cd "$build_dir"

echo "Installing tailwindcss@${TAILWIND_VERSION} and prismjs@${PRISM_VERSION}..."
npm install --no-audit --no-fund --silent \
  "tailwindcss@${TAILWIND_VERSION}" \
  "prismjs@${PRISM_VERSION}"

cat > tailwind.config.js <<'CONFIG'
module.exports = {
  content: ["./index.html"],
  theme: {
    extend: {
      fontFamily: {
        sans: ["ui-sans-serif", "system-ui", "sans-serif"],
        mono: ["ui-monospace", "SFMono-Regular", "Menlo", "monospace"],
      },
    },
  },
};
CONFIG

printf '@tailwind base;\n@tailwind components;\n@tailwind utilities;\n' > input.css

# Scanning index.html means only classes actually used are emitted. If a class
# disappears from the page after a rebuild, it was removed from the markup.
./node_modules/.bin/tailwindcss \
  -c tailwind.config.js \
  -i input.css \
  -o tailwind.out.css \
  --minify

out="${build_dir}/landing-assets"
mkdir -p "$out"
cp tailwind.out.css "${out}/01-tailwind.css"
cp node_modules/prismjs/themes/prism-tomorrow.min.css "${out}/02-prism-theme.css"
cp node_modules/prismjs/components/prism-core.min.js "${out}/03-prism-core.js"
cp node_modules/prismjs/components/prism-yaml.min.js "${out}/04-prism-yaml.js"

destination="${HOME}/hlinor-landing-assets"
rm -rf "$destination"
cp -r "$out" "$destination"

cat <<MSG

Built into ${destination}

Paste into index.html, replacing the current inline blocks:

  01-tailwind.css      -> first  <style> in <head>
  02-prism-theme.css   -> second <style> in <head>
  03-prism-core.js     -> first  <script> before </body>
  04-prism-yaml.js     -> second <script> before </body>

Then verify no external subresource crept back in:

  grep -nE '<script src=|<link[^>]*href="https?://' index.html

Only the canonical <link> should match. Anything else is a script or stylesheet
loaded from a third party, which is what this build exists to avoid.
MSG
