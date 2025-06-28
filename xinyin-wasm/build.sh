#!/bin/bash

wasm-pack build --no-pack --no-typescript -t web

# 将生成的 wasm 和 js 文件复制到指定目录
OUT_DIR=../../../web/xinyin-web
cp ./pkg/xinyin_wasm_bg.wasm "$OUT_DIR/xinyin_wasm_bg.wasm"
cp ./pkg/xinyin_wasm.js "$OUT_DIR/xinyin_wasm.js"

# 先在文件顶部插入 @ts-nocheck
# 在 macOS 的 BSD sed 中使用 -i '' 方式进行 inline 编辑
sed -i '' '1s/^/\/\/ @ts-nocheck\n/' "$OUT_DIR/xinyin_wasm.js"