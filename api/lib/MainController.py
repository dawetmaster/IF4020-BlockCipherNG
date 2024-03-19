from flask import Flask, request, flash, jsonify
from werkzeug.utils import secure_filename
from Cipher import Cipher
import time
import os
import uuid
import base64
import time


def register_controllers(app: Flask):
    @app.route("/")
    def main():
        return "Connected"

    @app.route("/encrypt", methods=["POST"])
    def encrypt():
        # baca plaintext
        plaintext = ""
        original_filename = ""
        if "file" in request.files:
            file = request.files["file"]
            if not file:
                flash("No file received")
                return "File not found", 400
            # baca file
            plaintext = file.stream.read()
            original_filename = file.filename
        else:
            # plaintext murni
            plaintext = str.encode(request.form["plaintext"])
        # baca mode
        mode = request.form["mode"]
        # baca key
        key = bytes(request.form["key"])
        # encrypt
        start_time = time.time()
        ciphertext = Cipher.encrypt(plaintext, key, mode)
        execution_time = time.time() - start_time
        # save temp file
        filename = ""
        if original_filename != "":
            names = original_filename.rsplit(".", 1)
            filename = f"{secure_filename(names[0])}-{str(int(time.time()))}-encrypted.{names[1]}"
        else:
            filename = f"{str(uuid.uuid4())}-encrypted.txt"
        # simpan dulu
        ciphertext_path = os.path.join(app.config["UPLOAD_PATH"], filename)
        with open(ciphertext_path, "wb") as f:
            f.write(ciphertext)
        # bikin json
        return jsonify(
            {"ciphertext": base64.b64encode(ciphertext), "elapsed_time": execution_time}
        )

    @app.route("/decrypt", methods=["POST"])
    def decrypt():
        pass

    @app.route("/download", methods=["GET"])
    def download():
        pass

    # if "files" not in request.files:
    #     flash("No file received")
    #     return redirect('/')
    #   archive = request.files['files']
    #   if(not archive):
    #     flash("No file received")
    #     return redirect('/')
    #   # pastikan file nya boleh diunggah
    #   if(not is_file_allowed(archive.filename)):
    #     flash("File not supported")
    #     return redirect('/')
    #   # rename
    #   names = archive.filename.rsplit('.',1)
    #   filename = f"{secure_filename(names[0])}-{str(int(time.time()))}.{names[1]}"
    #   # simpan dulu
    #   archive_path = os.path.join(app.config['UPLOAD_PATH'],filename)
    #   archive.save(archive_path)
    #   # parse file
    #   parser = FileParser(archive_path)
    #   parser.load()
    #   return "TBD"
