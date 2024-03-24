<script setup lang="ts">
import DecryptForm from '../components/DecryptForm.vue';
import { ref, Ref } from 'vue';
import axios from 'axios';

const output: Ref<string> = ref('');
const error_msg: Ref<string> = ref('');
async function handleEncryptionSubmission(formData: FormData) {
  // Handle form submission logic here
  console.log('Form data:', formData);
  await axios.postForm(
    import.meta.env.VITE_BE_BASE_URL + '/decrypt',
    formData,
    {
      headers: {'Content-Type': 'multipart/form-data'}
    }
  )
    .then((res) => {
      console.log(res.data)
      output.value = res.data;
    })
    .catch((err) => {
      const msg: string = `Error ${err.response.status} when fetching form submission: ${err.response.data}`
      console.error(msg);
      error_msg.value = msg;
    })
}
</script>

<template>
  <view class="flex flex-col">
    <h1 class="text-center text-xl text-black dark:text-white mb-4">Dekripsikan teks atau berkas Anda di sini...</h1>
    <DecryptForm id="decform" @decryption-submitted="handleEncryptionSubmission" />
    <div class="flex flex-col mt-8 gap-2">
      <label for="result-text" class="dark:text-white text-xl">Hasil Dekripsi</label>
      <textarea readonly id="result-text" class="rounded-md resize-y dark:bg-stone-800 dark:text-white dark:border-stone-600 dark:placeholder:text-stone-400">{{ output }}</textarea>
      <p class="text-red-600">{{ error_msg }}</p>
    </div>
  </view>
  
</template>