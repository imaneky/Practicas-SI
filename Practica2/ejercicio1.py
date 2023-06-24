from flask import Flask, redirect, url_for
from flask import render_template
from flask import request
from flask_login import LoginManager, current_user, login_user, logout_user, login_manager
from werkzeug.urls import url_parse
from forms import LoginForm, SignupForm
from login import users, get_user, User
import json
import sqlite3
import pandas as pd
import plotly.graph_objects as go
import requests
import re
import numpy as np
from matplotlib import pyplot as plt
from numpy import nan
import plotly.express as px
import json
import tempfile
from flask import Flask, render_template, jsonify, make_response
import sqlite3
import pandas as pd
import plotly.express as px
import plotly
import requests
import datetime
from apscheduler.schedulers.background import BackgroundScheduler
import plotly.io as pio
import os
from flask_weasyprint import HTML, render_pdf
import kaleido
import uuid


conexion = sqlite3.connect('alerts_database.db')
c = conexion.cursor()

alerts_df = pd.read_sql_query("SELECT * from alerts", conexion)
devices_df = pd.read_sql_query("SELECT * FROM devices", conexion)

