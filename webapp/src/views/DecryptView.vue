<script setup lang="ts">
import DecryptForm from '../components/DecryptForm.vue';
import { ref, Ref } from 'vue';
import axios from 'axios';

const output: Ref<string> = ref('');
const error_msg: Ref<string> = ref('');
const exec_time: Ref<string> = ref('');
const href_file: Ref<string> = ref('');
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
      output.value = res.data.ciphertext;
      exec_time.value = `Execution time: ${res.data.elapsed_time} seconds`;
      href_file.value = `${import.meta.env.VITE_BE_BASE_URL}/download/${res.data.download_filename}`;
      error_msg.value = '';
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
      <label for="result-text" class="dark:text-white text-xl">Hasil Dekripsi (dalam base64)</label>
      <textarea readonly id="result-text" class="rounded-md resize-y dark:bg-stone-800 dark:text-white dark:border-stone-600 dark:placeholder:text-stone-400">{{ output }}</textarea>
      <p class="dark:text-white">{{ exec_time }}</p>
      <a :href="href_file" v-if="href_file" class="text-black dark:text-white p-2 text-center drop-shadow-sm hover:drop-shadow-md rounded bg-stone-400 dark:bg-stone-600">Unduh berkas di sini</a>
      <p class="text-red-600">{{ error_msg }}</p>
    </div>
  </view>
  
</template>