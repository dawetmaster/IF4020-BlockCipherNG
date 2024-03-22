<script setup lang="ts">
import BaseForm from "./form/BaseForm.vue"
</script>

<template>
  <BaseForm
    textplaceholder="Tulis atau tempelkan ciphertext Anda di sini..."
    inputtextid="ciphertext" 
    keyplaceholder="Tulis atau tempelkan kunci Anda di sini..."
    b64checkplaceholder="Ciphertext ini dalam base64"
    formid="decryptform"
    @form-submitted="handleFormSubmission"
    >
  <slot></slot>
  </BaseForm>
</template>

<script lang="ts">
export default {
  components: {
    BaseForm
  },
  methods: {
    handleFormSubmission(formData: FormData) {
      this.$emit('encryption-submitted', formData);
    }
  }
}
</script>