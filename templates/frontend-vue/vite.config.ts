import vue from '@vitejs/plugin-vue'
import { defineConfig, mergeConfig } from 'vite'
import { sharedConfig } from './vite.shared.ts'

// 포트·프록시·CSP·빌드(소스맵 off, console 제거, vendor 분리) 설정은 vite.shared.ts 에 있다.
export default defineConfig(mergeConfig(sharedConfig(), { plugins: [vue()] }))
