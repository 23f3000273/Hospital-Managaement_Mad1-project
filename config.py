from dotenv import load_dotenv
import os
from app import app

load_dotenv()

app.config['SECRET_KEY']=os.getenv('SECRET_KEY')
app.config['SQLALCHEMY_DATABASE_URI']=os.getenv('SQLALCHEMY_DATABASE_URI')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS']=os.getenv('SQLALCHEMY_TRACK_MODIFICATIONS')
#app.config['WKHTMLTOPDF_PATH'] = os.getenv('WKHTMLTOPDF_PATH')

#app.config['DOWNLOAD_FOLDER'] = os.getenv('DOWNLOAD_FOLDER')