#!/bin/bash

# Xóa các file log/aux cũ để tránh xung đột (tùy chọn)
rm -f *.aux *.log *.out *.toc *.xdv *.fls *.fdb_latexmk

echo "Đang biên dịch lần 1 (tạo cấu trúc và references)..."
xelatex -interaction=nonstopmode main.tex

echo "Đang biên dịch lần 2 (cập nhật Table of Contents và references)..."
xelatex -interaction=nonstopmode main.tex

echo "Biên dịch hoàn tất! File kết quả: main.pdf"
