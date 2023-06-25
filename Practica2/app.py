import json
import tempfile
from flask import Flask, render_template, jsonify, abort, make_response
from flask_bootstrap import Bootstrap
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
import os



app = Flask(__name__)

con = sqlite3.connect('../Practica1/alerts_database.db')
cur = con.cursor()
alerts_df = pd.read_sql_query("SELECT * from alerts", con)
devices_df = pd.read_sql_query(
    "SELECT id, SUM(analisisServiviosInseguros + analisisVulnerabilidades) as numero_vulnerabilidades FROM DEVICES GROUP BY id ORDER BY numero_vulnerabilidades ",
    con)
df_devices = pd.read_sql_query("SELECT * from devices", con)
vulnerabilidades = []
last_updated_cve = ""
numIP = 10
numDevice = 5
numPeligrosos = 3
numSeguros = 3


@app.route('/')
def index():
    # Get the JSON data for the initial chart
    chartIPJSON = chart_IP(numIP)
    chartDevicesJSON = chart_devices(numDevice)
    chartDangerousJSON = chart_dangerous(numPeligrosos)
    chartSecureJSON = chart_secure(numSeguros)
    chartTotalSecurityJSON = chart_total_security()

    return render_template('index.html', chartIPJSON=chartIPJSON, numIP=numIP,
                           chartDevicesJSON=chartDevicesJSON, numDevice=numDevice,
                           chartDangerousJSON=chartDangerousJSON, numPeligrosos=numPeligrosos,
                           chartSecureJSON=chartSecureJSON, numSeguros=numSeguros,
                           chartTotalSecurityJSON=chartTotalSecurityJSON,
                           vulnerabilidades=vulnerabilidades, last_updated_cve=last_updated_cve)


@app.route('/chart_IP/<int:num>')
def chart_IP(num):
    global numIP
    numIP = num
    ip_mas_problematicas_df = alerts_df[alerts_df['prioridad'] == 1]
    ip_mas_problematicas_df = ip_mas_problematicas_df.groupby('origen')['sid'].count().reset_index(name='numero_alertas')
    #ip_mas_problematicas_counts = ip_mas_problematicas_df['origen'].value_counts().head(numIP)
    ip_mas_problematicas_df.sort_values(by=['numero_alertas'], ascending=False, inplace=True)

    fig = px.bar(ip_mas_problematicas_df.head(numIP), x='origen', y='numero_alertas', barmode='group',labels=dict(origen="IP", numero_alertas="Número de alertas"))
    #fig = px.bar(x=ip_mas_problematicas_df.index, y=ip_mas_problematicas_counts.values, labels={'x': 'IP', 'y': 'Nº de alertas'})

    chartJSON = json.dumps(fig, cls=plotly.utils.PlotlyJSONEncoder)

    return chartJSON


@app.route('/chartDevices/<int:num>')
def chart_devices(num):
    global numDevice
    numDevice = num
    dispositivos_vulnerables_df = devices_df.groupby('id')['numero_vulnerabilidades'].sum().reset_index(name='numero_vulnerabilidades')
    dispositivos_vulnerables_df.sort_values(by=['numero_vulnerabilidades'], ascending=False, inplace=True)
    fig = px.bar(dispositivos_vulnerables_df.head(numDevice), x='id', y='numero_vulnerabilidades', barmode='group',labels=dict(id="Dispositivo", numero_vulnerabilidades="Número de vulnerabilidades"))

    chartJSON = json.dumps(fig, cls=plotly.utils.PlotlyJSONEncoder)
    return chartJSON


@app.route('/chartDangerous/<int:amount>')
def chart_dangerous(amount):
    global numPeligrosos
    numPeligrosos = amount
    dispositivos_peligrosos_df = devices_df[devices_df['numero_vulnerabilidades'] > 0]
    dispositivos_peligrosos_df.sort_values(by=['numero_vulnerabilidades'], ascending=False, inplace=True)
    fig = px.bar(dispositivos_peligrosos_df.head(numPeligrosos), x='id', y='numero_vulnerabilidades', barmode='group',
                 labels=dict(id="Dispositivo", numero_vulnerabilidades="Nº de vulnerabilidades"))

    chartJSON = json.dumps(fig, cls=plotly.utils.PlotlyJSONEncoder)
    return chartJSON


@app.route('/chartSecure/<int:amount>')
def chart_secure(amount):
    global numSeguros
    numSeguros = amount
    dispositivos_seguros_df = devices_df[devices_df['numero_vulnerabilidades'] == 0]
    dispositivos_seguros_df.sort_values(by=['numero_vulnerabilidades'], ascending=False, inplace=True)
    fig = px.bar(dispositivos_seguros_df.head(numSeguros), x='id', y='numero_vulnerabilidades', barmode='group',
                 labels=dict(id="Dispositivo", numero_vulnerabilidades="Nº vulnerabilidades"))

    chartJSON = json.dumps(fig, cls=plotly.utils.PlotlyJSONEncoder)
    return chartJSON


@app.route('/chartTotalSecurity')
def chart_total_security():
    dispositivos_seguros_df = devices_df[devices_df['numero_vulnerabilidades'] == 0]
    dispositivos_peligrosos_df = devices_df[devices_df['numero_vulnerabilidades'] > 0]

    num_seguros = len(dispositivos_seguros_df)
    num_peligrosos = len(dispositivos_peligrosos_df)

    data = {'Estado': ['Seguros', 'Peligrosos'], 'Cantidad': [num_seguros, num_peligrosos]}
    df = pd.DataFrame(data)

    fig = px.pie(df, values='Cantidad', names='Estado', title='Dispositivos Seguros vs. Peligrosos')

    chartJSON = json.dumps(fig, cls=plotly.utils.PlotlyJSONEncoder)
    return chartJSON


def vulnerabilidades_cve():
    global vulnerabilidades
    global last_updated_cve

    response = requests.get("https://cve.circl.lu/api/last")

    if response.status_code == 200:
        data = response.json()
        data_sorted = sorted(data, key=lambda x: x['Published'], reverse=True)
        last_10_data = data_sorted[:10]
        vulnerabilidades = []

        for i in range(10):
            vulnerability = {"id": last_10_data[i]["id"], "summary": last_10_data[i]["summary"]}

            fecha_publicacion = datetime.datetime.fromisoformat(last_10_data[i]["Published"])
            vulnerability["fecha_publicacion"] = fecha_publicacion.strftime('%d-%m-%Y %H:%M')
            vulnerability["url"] = f"https://cve.circl.lu/cve/{last_10_data[i]['id']}"
            vulnerabilidades.append(vulnerability)

        last_updated_cve = datetime.datetime.now().strftime('%d-%m-%Y %H:%M:%S')


# -------------- EJERCICIO 4 --------------
#  Distribución de las clasificaciones de alertas más comunes
@app.route('/chartClassification/<int:num>')
def chartClassification(num):
    clasification_df = alerts_df.groupby('clasificacion')['sid'].count().reset_index(name='cantidad')
    clasification_df.sort_values(by=['cantidad'], ascending=False, inplace=True)

    fig = px.bar(clasification_df.head(num), x='clasificacion', y='cantidad',
                 labels=dict(clasificacion="Clasificación", cantidad="Cantidad"))

    chartJSON = json.dumps(fig, cls=plotly.utils.PlotlyJSONEncoder)
    return chartJSON


#
@app.route('/chartTemporalEvolution')
def chartTemporalEvolution():
    alertas_por_fecha = alerts_df.groupby('timestamp').size().reset_index(name='cantidad')
    alertas_por_fecha['timestamp'] = pd.to_datetime(alertas_por_fecha['timestamp'])

    fig = px.line(alertas_por_fecha, x='timestamp', y='cantidad',
                  labels=dict(timestamp="Fecha", cantidad="Cantidad de Alertas"))

    chartJSON = json.dumps(fig, cls=plotly.utils.PlotlyJSONEncoder)
    return chartJSON


@app.route('/mapaDispositivos')
def mapaDispositivos():
    dispositivos_df = devices_df.copy()

    # Eliminar las filas que no tienen información de ubicación
    dispositivos_df = dispositivos_df[dispositivos_df['localizacion'] != 'None']

    # Obtener las coordenadas geográficas (latitud, longitud) de cada ubicación
    geolocator = Nominatim(user_agent="my_app")
    dispositivos_df['geolocation'] = dispositivos_df['localizacion'].apply(lambda x: geolocator.geocode(x))
    dispositivos_df['latitude'] = dispositivos_df['geolocation'].apply(lambda x: x.latitude if x else None)
    dispositivos_df['longitude'] = dispositivos_df['geolocation'].apply(lambda x: x.longitude if x else None)

    # Crear el mapa interactivo utilizando la biblioteca folium
    mapa = folium.Map(location=[dispositivos_df['latitude'].mean(), dispositivos_df['longitude'].mean()], zoom_start=4)

    # Agregar un marcador por cada dispositivo con información de ubicación
    for i, row in dispositivos_df.iterrows():
        if row['latitude'] and row['longitude']:
            folium.Marker([row['latitude'], row['longitude']], popup=row['localizacion']).add_to(mapa)

    # Guardar el mapa como un archivo HTML
    mapa_html = mapa.get_root().render()

    return mapa_html


def obtener_top_clasificaciones():
    alertas_categoria_df = alerts_df.groupby('clasificacion')['clasificacion'].count().reset_index(name='numero_alertas')
    alertas_categoria_df = alertas_categoria_df.sort_values(by='numero_alertas', ascending=False).head(3)

    return alertas_categoria_df


def obtener_informacion_wikipedia(clasificacion):
    url = f'https://es.wikipedia.org/w/api.php?action=opensearch&search={clasificacion}&limit=1&format=json'

    try:
        response = requests.get(url)
        if response.status_code == 200:
            info = response.json()
            if len(info) > 2:
                return info[2][0]
            else:
                return ""
        else:
            return ""
    except requests.RequestException:
        return ""


def buscar_tweets(clasificacion):
    url = f'https://api.twitter.com/1.1/search/tweets.json?q={clasificacion}'

    try:
        response = requests.get(url)
        if response.status_code == 200:
            tweets = [tweet['text'] for tweet in response.json()['statuses']]
            return tweets
        else:
            return []
    except requests.RequestException:
        return []


@app.route('/chart_top_alertas')
def chart_top_alertas():
    top_clasificaciones = obtener_top_clasificaciones()
    clasificaciones = top_clasificaciones['clasificacion']
    porcentajes = top_clasificaciones['numero_alertas'] / top_clasificaciones['numero_alertas'].sum() * 100

    # Configurar el gráfico
    fig, ax = plt.subplots(figsize=(8, 8))
    wedges, _, autotexts = ax.pie(porcentajes, labels=clasificaciones, startangle=90,
                                  autopct='%1.1f%%', textprops={'fontsize': 'small'})
    ax.axis('equal')
    plt.title('Top 3 de Alertas')

    # Añadir porcentajes en el gráfico
    for autotext in autotexts:
        autotext.set_color('white')

    # Obtener información de Wikipedia y tweets para cada clasificación
    info_wikipedia = [obtener_informacion_wikipedia(clasificacion) for clasificacion in clasificaciones]
    tweets = [buscar_tweets(clasificacion) for clasificacion in clasificaciones]

    return jsonify({
        'grafico': plt,
        'info_wikipedia': info_wikipedia,
        'tweets': tweets
    })


if __name__ == '__main__':

    vulnerabilidades_cve()
    app.run(port=80, debug=True)

