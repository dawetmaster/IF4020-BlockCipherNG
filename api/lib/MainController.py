from flask import Flask,render_template,request,flash,redirect
from werkzeug.utils import secure_filename
import time
import os

def register_controllers(app:Flask):
  @app.route('/')
  def main():
    return "Connected"
  
  # @app.route('/analyze',methods=["POST"])
  # def analyze_code():
  #   if "files" not in request.files:
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
  
  # def is_file_allowed(filename:str):
  #   return '.' in filename and filename.rsplit('.',1)[1].lower() in ALLOWED_EXTENSION