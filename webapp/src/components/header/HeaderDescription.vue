<script setup lang="ts">
defineProps<{
  text: string
}>()
</script>

<template>
  <div class="text-center text-white">{{ text }}</div>
</template>