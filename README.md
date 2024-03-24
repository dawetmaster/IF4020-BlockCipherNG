# Tugas 3 IF4020 Kriptografi - NGAWICrypt

## Ikhtisar
NGAWICrypt (IPA: /ŋawikrɪp/) adalah sebuah inovasi kami di bidang kriptografi. Sebagaimana algoritma kriptografi pada umumnya, NGAWICrypt mengenkripsi pesan sehingga tidak mudah dibaca oleh pihak ketiga. 

## Penjenamaan
NGAWICrypt merupakan singkatan dari *New Generation Advanced Wiguna Cryptography*. *New Generation* berarti generasi terbaru, *Advanced* berarti maju dan terdepan, *Wiguna* (dari bahasa Sanskerta) berarti berguna, dan *Cryptography* berarti kriptografi.

Nama *Ngawi* ini kami pilih berdasarkan sebuah kabupaten di Jawa Timur yang selalu memberi cerita dalam perjalanan jauh. Ngawi menjadi salah satu tempat istirahat bagi bus antarkota dari dan ke arah Jakarta menuju Jawa Timur dan Bali.

## Prinsip Utama
Berikut ini prinsip utama dari NGAWICrypt:

1. Prinsip Confusion dan Diffusion Shanon
2. Dapat melakukan enkripsi dan dekripsi dengan 5 mode, yakni **ECB**,**CBC**,**CFB**,**OFB**, dan **CTR**.
3. Ruang kunci sebanyak 128-bit.
4. Efek longsoran yang signifikan.
5. Waktu eksekusi yang bagus.

## Kebutuhan
Berikut ini kebutuhan dalam *development* NGAWICrypt:
### *Development*
- `pnpm`
  - `vue`
  - `tailwind`
- `python`

## Cara menjalankan
Untuk menjalankan _frontend_, berikut langkahnya:
1. tambahkan _file_ `.env` pada _folder_ `webapp`. Untuk informasi apa saja yang perlu ada di _file_ `.env`, bisa melihat isi _file_ `.env.example`.
2. Pindah ke _folder_ `webapp` lalu unduh _dependency_ yang dibutuhkan:
```sh
cd webapp
pnpm install
```
3. Jalankan perintah berikut:
```sh
pnpm run dev
```
4. Masuk ke tautan yang muncul di _command line_. Secara _default_ berada pada _port_ 5173.
http://localhost:5173/

Untuk menjalankan _backend_, berikut langkahnya:
1. tambahkan _file_ `.env` pada _folder_ `api`. Untuk informasi apa saja yang perlu ada di _file_ `.env`, bisa melihat isi _file_ `.env.example`.
2. Pindah ke _folder_ `api` lalu unduh _dependency_ yang dibutuhkan:
```sh
cd api
pip install -r requirements.txt
```
3. Jalankan perintah berikut:
```sh
python main.py
```

## Tentang Kami

1. 13520005 - Christine Hutabarat
2. 13520086 - Fawwaz Anugerah Wiradhika D
3. 13520098 - Andika Naufal Hilmy
