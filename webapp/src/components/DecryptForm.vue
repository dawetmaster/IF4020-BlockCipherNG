<script setup lang="ts">
import BaseForm from "./form/BaseForm.vue"
</script>

<template>
  <BaseForm
    textplaceholder="Tulis atau tempelkan ciphertext Anda di sini..." 
    keyplaceholder="Tulis atau tempelkan kunci Anda di sini..."
    b64checkplaceholder="Ciphertext ini dalam base64"
  />
</template>