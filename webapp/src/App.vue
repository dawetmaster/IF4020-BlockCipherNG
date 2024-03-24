<script setup lang="ts">
  import { RouterView } from 'vue-router'
  import Header from './components/Header.vue'
  
  console.log(import.meta.env.VITE_BE_BASE_URL)
</script>

<template>
  <main class="flex flex-col min-h-screen">
    <Header />
    <div class="grow bg-stone-100 dark:bg-stone-800 p-8">
      <div class="max-w-screen-lg mx-auto">
        <RouterView />
      </div>
    </div>
  </main>
</template>
