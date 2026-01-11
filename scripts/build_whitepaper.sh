#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
wp_dir="$repo_root/whitepaper"

cd "$wp_dir"
latexmk -pdf Parcela-Whitepaper.tex

cp "$wp_dir/Parcela-Whitepaper.pdf" "$repo_root/docs/Parcela-Whitepaper.pdf"

latexmk -c Parcela-Whitepaper.tex
