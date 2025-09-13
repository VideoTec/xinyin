#!/bin/bash

wasm-pack build --no-pack --out-name xinyin-wasm -t web

# 将生成的 wasm 和 js 文件复制到指定目录
OUT_DIR=../../../web/xinyin-web/src/xinyin
cp ./pkg/xinyin-wasm_bg.wasm "$OUT_DIR/../../public/xinyin-wasm.wasm"
cp ./pkg/xinyin-wasm_bg.wasm.d.ts "$OUT_DIR/xinyin-wasm.wasm.d.ts"
cp ./pkg/xinyin-wasm.js "$OUT_DIR/xinyin-wasm.js"
cp ./pkg/xinyin-wasm.d.ts "$OUT_DIR/xinyin-wasm.d.ts"

# 先在文件顶部插入 @ts-nocheck
# 在 macOS 的 BSD sed 中使用 -i '' 方式进行 inline 编辑
sed -i '' '1s/^/\/\/ @ts-nocheck\n/' "$OUT_DIR/xinyin-wasm.js"