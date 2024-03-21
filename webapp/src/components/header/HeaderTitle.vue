<script setup lang="ts">
defineProps<{
  title: string
}>()
</script>

<template>
  <div class="text-4xl text-white text-center pb-4"><b>{{ title }}</b></div>
</template>