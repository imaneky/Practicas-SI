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



app = Flask(__name__)


conexion = sqlite3.connect('alerts_database.db')
c = conexion.cursor()

alerts_df = pd.read_sql_query("SELECT * from alerts", conexion)
devices_df = pd.read_sql_query("SELECT * FROM devices", conexion)

dispositivos_vulnerables_df = pd.read_sql_query('SELECT id, SUM(analisisServiviosInseguros + analisisVulnerabilidades) as num_vulnerabilidades FROM devices GROUP BY id ORDER BY num_vulnerabilidades', conexion)

vulnerabilities = []
last_updated_cve = ""
numIP = 10
numDevices = 5
numPeligroso = 3
numSeguro = 3

############################ FUNCIONES ################################

@app.route('/index')
def index():
    return render_template('index.html')

@app.route('/ipProblematica/<int:num>')
def ipProblematica(num):
    global numIP
    numIP = num
    ip_mas_problematicas_df = alerts_df[alerts_df['prioridad'] == 1]
    ip_mas_problematicas_df = ip_mas_problematicas_df.groupby('origen')['sid'].count().reset_index(name='numero_alertas')
    ip_mas_problematicas_df.sort_values(by=['numero_alertas'], ascending=False, inplace=True)
    fig = px.bar(ip_mas_problematicas_df.head(numIP), x='origen', y='numero_alertas', labels=dict(origen="IP", numero_alertas="Número de alertas"))
    json_grafico = json.dumps(fig, cls=plotly.utils.PlotlyJSONEncoder)
    return json_grafico




########################################################################
@app.route('/')
def hello():
    return 'Hi everyone :)'

@app.route('/graphIP/<int:quantity>')
def graphIP(quantity):
    global numIP
    numIP = quantity
    ip_mas_problematicas_df = alerts_df[alerts_df['prioridad'] == 1]
    ip_mas_problematicas_df = ip_mas_problematicas_df.groupby('origen')['sid'].count().reset_index(
        name='numero_alertas')
    ip_mas_problematicas_df.sort_values(by=['numero_alertas'], ascending=False, inplace=True)

    fig = px.bar(ip_mas_problematicas_df.head(numIP), x='origen', y='numero_alertas', barmode='group',
                 labels=dict(origen="IP", numero_alertas="Número de alertas"))

    graphJSON = json.dumps(fig, cls=plotly.utils.PlotlyJSONEncoder)
    return graphJSON


if __name__ == '__main__':
    # Create a scheduler object

    # Add a job to the scheduler to update the vulnerabilities every minute

    graphIP(5)
    app.debug = True
    app.run()


