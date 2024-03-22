<script setup lang="ts">
import HeaderTitle from './header/HeaderTitle.vue';
import HeaderDescription from './header/HeaderDescription.vue';
import { RouterLink } from 'vue-router'
</script>

<template>
  <div class="p-8 bg-rose-600 dark:bg-rose-900">
    <HeaderTitle title="NGAWICrypt" />
    <HeaderDescription text="NGAWICrypt (IPA: /ŋawikrɪp/) adalah sebuah inovasi kami di bidang kriptografi. Sebagaimana algoritma kriptografi pada umumnya, NGAWICrypt mengenkripsi pesan sehingga tidak mudah dibaca oleh pihak ketiga." />
  </div>
  <div class="py-2 bg-rose-400 dark:bg-rose-800">
    <nav class="flex justify-center gap-4 text-white">
      <RouterLink :class="{'font-bold':($route.path === '/')}" to="/">Encrypt</RouterLink>
      <RouterLink :class="{'font-bold':($route.path === '/decrypt')}" to="/decrypt">Decrypt</RouterLink>
    </nav>
  </div>
</template>