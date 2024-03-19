from flask import Flask,render_template,request,flash,redirect
from werkzeug.utils import secure_filename
import time
import os

def register_controllers(app:Flask):
  @app.route('/')
  def main():
    return "Connected"
  
  @app.route('/encrypt', methods=["POST"])
  def encrypt():
    pass
  
  @app.route('/decrypt', methods=["POST"])
  def decrypt():
    pass