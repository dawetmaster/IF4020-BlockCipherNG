<script setup lang="ts">
  import { RouterView } from 'vue-router'
  import Header from './components/Header.vue'
  // import Footer from './components/Footer.vue'
  // import EncryptView from './views/EncryptView.vue';
</script>

<template>
  <main class="flex flex-col min-h-screen">
    <Header class="grow-0" />
    <div class="grow bg-stone-100 dark:bg-stone-800 p-8">
      <div class="max-w-screen-lg mx-auto">
        <RouterView />
      </div>
    </div>
  </main>
</template>
