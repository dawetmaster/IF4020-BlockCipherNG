import { createRouter, createWebHistory } from 'vue-router'
import EncryptView from '../views/EncryptView.vue'
import DecryptView from '../views/DecryptView.vue'

const router = createRouter({
  history: createWebHistory(import.meta.env.BASE_URL),
  routes: [
    {
      path: '/',
      name: 'encrypt',
      component: EncryptView
    },
    {
      path: '/decrypt',
      name: 'decrypt',
      component: DecryptView
    },
  ]
})

export default router