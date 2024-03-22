<script setup lang="ts">
defineProps<{
  textplaceholder: string,
  keyplaceholder: string,
  b64checkplaceholder: string,
  inputtextid?: string,
  formid: string,
}>()
</script>

<template>
  <form class="justify-center flex flex-col gap-4" :id="formid" @submit.prevent="submitForm">
    <div class="flex gap-2 sm:gap-4 flex-col sm:flex-row">
      <div class="grid gap-2 grow">
        <textarea :id="inputtextid" v-model="inputtext" class="rounded-md shadow-sm focus:border-rose-300 dark:focus:border-rose-500 focus:ring focus:ring-rose-200 dark:focus:ring-rose-400 focus:ring-opacity-50 resize-none dark:bg-stone-700 dark:text-white dark:border-stone-400 dark:placeholder:text-stone-400" :placeholder="textplaceholder"></textarea>
        <div class="flex gap-2 items-center">
          <input type="checkbox" id="base64" name="base64" v-model="base64check" class="rounded border-gray-300 text-rose-600 shadow-sm focus:border-rose-300 dark:focus:border-rose-500 focus:ring focus:ring-offset-0 focus:ring-rose-200 dark:focus:ring-rose-400 focus:ring-opacity-50">
          <label for="base64" class="dark:text-white">{{ b64checkplaceholder }}</label>
        </div>
      </div>
      <div class="grid gap-2">
        <label class="dark:text-white" for="file-input">Atau cukup unggah file Anda di sini...</label>
        <input type="file" id="inputfile" @change="handleFileChange" class="file:bg-transparent file:border-black dark:file:border-stone-200 file:drop-shadow-sm file:p-2 file:hover:drop-shadow-md file:border-solid file:rounded file:focus:ring file:focus:ring-stone-900 dark:file:focus:ring-stone-200 file:focus:ring-opacity-50 dark:file:text-white file:mr-2 dark:text-white">
        <slot></slot>
      </div>
    </div>
    <input type="text" id="key" name="key" v-model="key" :placeholder="keyplaceholder" class="rounded-md shadow-sm focus:border-rose-300 dark:focus:border-rose-500 focus:ring focus:ring-rose-200 dark:focus:ring-rose-400 dark:bg-stone-700 dark:text-white dark:border-stone-400 dark:placeholder:text-stone-400">
    <input type="submit" class="text-white bg-rose-600 dark:bg-rose-800 rounded drop-shadow-sm hover:drop-shadow-md p-2">
  </form>
</template>

<script lang="ts">
export default {
  data() {
    return {
      inputtext: '',
      base64check: '',
      key: '',
      file: null,
    }
  },
  methods: {
    submitForm() {
      this.$emit('form-submitted', { inputtext: this.inputtext, key: this.key, file: this.file });
    },
    handleFileChange(event: any) {
      this.file = event.target.files[0];
    }
  }
}
</script>