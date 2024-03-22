<template>
  <form class="justify-center flex flex-col gap-4">
    <div class="flex gap-4">
      <div class="grid gap-2 grow">
        <textarea id="plaintext" class="form-textarea simple resize-none dark:bg-stone-700 dark:text-white dark:border-stone-400 dark:placeholder:text-stone-400" placeholder="Write your plaintext here..."></textarea>
        <div class="flex gap-2 items-center">
          <input type="checkbox" id="base64" name="base64">
          <label for="base64" class="dark:text-white">The plaintext is in Base64</label>
        </div>
      </div>
      <div class="grid gap-2">
        <label class="dark:text-white" for="file-input">Or just upload file here...</label>
        <input type="file" id="file-input" class="file:bg-transparent file:border-black dark:file:border-stone-200 file:drop-shadow-sm file:p-2 file:hover:drop-shadow-md file:border-solid file:rounded dark:file:text-white file:mr-2 dark:text-white">
      </div>
    </div>
    <input type="text" id="key" name="key" placeholder="Write your key here..." class="simple dark:bg-stone-700 dark:text-white dark:border-stone-400 dark:placeholder:text-stone-400">
    <input type="submit" class="dark:text-white bg-rose-600 dark:bg-rose-900 rounded drop-shadow-sm hover:drop-shadow-md p-2">
  </form>
</template>

<style scoped>
/* @media (prefers-color-scheme: dark) {
  input[type=file]::file-selector-button {
  }
} */
</style>