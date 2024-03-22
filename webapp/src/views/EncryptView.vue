<script setup lang="ts">
import EncryptForm from '../components/EncryptForm.vue';
</script>

<template>
  <view class="flex flex-col">
    <h1 class="text-center text-xl text-black dark:text-white mb-4">Enkripsikan teks atau berkas Anda di sini...</h1>
    <EncryptForm id="encform" @encryption-submitted="handleEncryptionSubmission" />
    <div class="flex flex-col mt-8 gap-2">
      <label class="dark:text-white text-xl">Hasil Enkripsi</label>
      <textarea readonly id="result-text" class="rounded-md resize-y dark:bg-stone-800 dark:text-white dark:border-stone-600 dark:placeholder:text-stone-400"></textarea>
    </div>
  </view>
</template>

<script lang="ts">
export default {
  components: {
    EncryptForm
  },
  methods: {
    handleEncryptionSubmission(formData: FormData) {
      // Handle form submission logic here
      console.log('Form data:', formData);
    }
  }
}
</script>