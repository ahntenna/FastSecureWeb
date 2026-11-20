import { createApp } from 'vue'
import App from './App.vue'
import { startGuard } from './security/guard'
import './style.css'

startGuard() // 운영 빌드에서만 동작한다
createApp(App).mount('#app')
