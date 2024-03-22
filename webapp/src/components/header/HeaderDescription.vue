<script setup lang="ts">
defineProps<{
  text: string
}>()
</script>

<template>
  <div class="text-center text-white max-w-screen-lg mx-auto">{{ text }}</div>
</template>