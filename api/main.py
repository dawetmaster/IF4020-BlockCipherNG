from flask import Flask
from flask_cors import CORS
from lib.MainController import register_controllers
from dotenv import load_dotenv
import os

def create_app():
  cors_src = os.getenv("CORS_SRC")
  print(cors_src)
  app = Flask(__name__)
  CORS(app, resources={r"/*": {"origins": cors_src}})

  # register routes
  register_controllers(app)

  #set config
  app.config['UPLOAD_PATH'] = os.path.join(app.instance_path.replace("\\instance",""),os.getenv('UPLOAD_FOLDER'))
  
  return app

if(__name__=="__main__"):
  load_dotenv()
  debug_mode = bool(int(os.getenv("DEBUG")))
  app = create_app()
  app.run(debug=debug_mode)