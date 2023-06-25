import sqlite3
import datetime
import numpy as np
import pandas as pd
import requests
from matplotlib import pyplot as plt
import urllib.parse

con = sqlite3.connect('alerts_database.db')
cur = con.cursor()
alerts_df = pd.read_sql_query("SELECT * from alerts", con)
df_devices = pd.read_sql_query("SELECT * from devices", con)


def obtener_informacion_wikipedia(puerto):
    url = f'https://es.wikipedia.org/w/api.php?action=query&list=search&srprop=snippet&format=json&origin=*&utf8=&srsearch={puerto}'

    try:
        response = requests.get(url)
        if response.status_code == 200:
            data = response.json()
            if 'query' in data and 'search' in data['query']:
                results = data['query']['search']
                if len(results) > 0:
                    result = results[0]
                    title = result['title']
                    snippet = result['snippet']
                    pageid = result['pageid']
                    article_url = f'https://es.wikipedia.org/wiki/{title.replace(" ", "_")}'
                    return title, snippet, article_url
                else:
                    return "", "", ""
            else:
                return "", "", ""
        else:
            return "", "", ""
    except requests.RequestException:
        return "", "", ""


# TOP X ALERTAS - GENERA UN GRÁFICO CON EL TOP DE ALERTAS DE LA BASE DE DATOS, EN PORCENTAJES
alertas_categoria_df = alerts_df.groupby('clasificacion')['clasificacion'].count().reset_index(name='numero_alertas')

# Obtener los datos de las categorias y los numeros de alertas
categorias = alertas_categoria_df['clasificacion']
num_alertas = alertas_categoria_df['numero_alertas']

# Calcular los porcentajes correspondientes a cada categoria
total_alertas = sum(num_alertas)
porcentajes = [(num / total_alertas) * 100 for num in num_alertas]
porcentajes_str = [f'{porcentaje:.2f}%' for porcentaje in porcentajes]

# Ordenar las categorías y porcentajes de forma descendente por los porcentajes
sorted_data = sorted(zip(categorias, porcentajes_str), key=lambda x: float(x[1][:-1]), reverse=True)

# Obtener solo los primeros X elementos
topX = 3
topx_data = sorted_data[:topX]

# Extraer las categorías y porcentajes del top 3
topx_categorias, topx_porcentajes = zip(*topx_data)

# Convertir los porcentajes a valores numéricos
top3_porcentajes_float = [float(porcentaje[:-1]) for porcentaje in topx_porcentajes]

# Configurar el gráfico
fig, ax = plt.subplots(figsize=(10, 10))
explode = [0.1] * len(topx_categorias)
wedges, texts, autotexts = ax.pie(top3_porcentajes_float, labels=topx_categorias, startangle=90,
                                  explode=explode, autopct='%1.1f%%', textprops={'fontsize': 'small'})
ax.axis('equal')
plt.title('Porcentaje top alertas por categoría')

# Añadir leyenda
legend_labels = [f'{categoria}: {porcentaje}' for categoria, porcentaje in zip(topx_categorias, topx_porcentajes)]
plt.legend(wedges, legend_labels, loc='center left', bbox_to_anchor=(1, 0.5), title='Categorías y Porcentajes',
           fontsize='small')
plt.tight_layout()  # Ajustar el espacio para evitar que los nombres se superpongan


plt.show()


# TOP puertos abiertos - GENERA UN GRÁFICO DESCENDENTE DE LOS PUERTOS ABIERTOS Y LAS VECES QUE APARECEN
# EN LA TABLA DEVICES-> SE OBSERVA LA FRECUENCIA
df_puertos_abiertos = df_devices[['analisisPuertosAbiertos']]

# Separar los puertos en una lista y eliminar los corchetes y el valor 'NULL'
puertos = []
for lista_puertos in df_puertos_abiertos['analisisPuertosAbiertos']:
    if lista_puertos is not None:
        lista_puertos = lista_puertos.strip("[]").replace("'", "")
        puertos.extend(lista_puertos.split(','))

# Contar la frecuencia de cada puerto
puertos_frecuencia = {}
for puerto in puertos:
    puerto = puerto.strip()
    if puerto != 'NULL':
        puertos_frecuencia[puerto] = puertos_frecuencia.get(puerto, 0) + 1

# Ordenar los puertos por frecuencia de manera descendente
puertos_ordenados = sorted(puertos_frecuencia.items(), key=lambda x: x[1], reverse=True)
puertos = [puerto[0] for puerto in puertos_ordenados]
frecuencias = [puerto[1] for puerto in puertos_ordenados]

# Configurar el gráfico
fig, ax = plt.subplots(figsize=(10, 6))
x_pos = np.arange(len(puertos))
ax.bar(x_pos, frecuencias, align='center')

# Configurar los ejes y el título
plt.xlabel('Puertos')
plt.ylabel('Frecuencia')
plt.title('Frecuencia de puertos abiertos')

# Ajustar las etiquetas del eje x
plt.xticks(x_pos, puertos, rotation=90)

plt.show()


# INFO WIKI - UTILIZA LA API DE WIKI PARA MOSTRAR ARTÍCULOS RELACIONADOS CON LOS PUERTOS ABIERTOS MÁS FRECUENTES
# Obtener los x primeros puertos
x = 3  # Cambiar el valor según necesidades
puertos_primeros = puertos[:x]

# Obtener la información de Wikipedia para los primeros puertos
info_wikipedia = []
for puerto in puertos_primeros:
    titulo, fragmento, enlace = obtener_informacion_wikipedia(puerto)
    info_wikipedia.append((titulo, fragmento, enlace))

# Imprimir los resultados
print("Artículos relacionados con los puertos abiertos")
for titulo, fragmento, enlace in info_wikipedia:
    print("Título:", titulo)
    print("Fragmento:", fragmento)
    print("Enlace:", enlace)
    print()


# API Have I been pwned - DEVUEVE LA ÚLTIMAS 20 BRECHAS DE SEGURIDAD REGISTRADAS, Y UN ENLACE A CADA NOTICIA
def obtener_brechas_de_seguridad():
    url = 'https://haveibeenpwned.com/api/v3/breaches'
    try:
        response = requests.get(url)
        if response.status_code == 200:
            brechas = response.json()
            return brechas
        else:
            print('Error en la solicitud:', response.status_code)
            return []
    except requests.RequestException as e:
        print('Error de conexión:', str(e))
        return []


def filtrar_por_fecha(brechas):
    # Obtener la fecha actual
    fecha_actual = datetime.datetime.now().date()

    # Filtrar las brechas por fecha y obtener las más recientes
    brechas_filtradas = []
    for brecha in brechas:
        fecha_brecha = datetime.datetime.strptime(brecha['BreachDate'], '%Y-%m-%d').date()
        if fecha_brecha <= fecha_actual:
            brechas_filtradas.append(brecha)

    # Ordenar las brechas por fecha (de la más reciente a la más antigua)
    brechas_ordenadas = sorted(brechas_filtradas, key=lambda x: datetime.datetime.strptime(x['BreachDate'], '%Y-%m-%d'), reverse=True)

    # Devolver las primeras 20 brechas de seguridad
    return brechas_ordenadas[:20]


# Obtener todas las brechas de seguridad
brechas = obtener_brechas_de_seguridad()

# Filtrar y ordenar las brechas por fecha
brechas_recientes = filtrar_por_fecha(brechas)

# Imprimir las brechas de seguridad recientes
print("Top 20 Brechas de seguridad")
for brecha in brechas_recientes:
    print('Nombre:', brecha['Name'])
    print('Fecha de la brecha:', brecha['BreachDate'])
    print('Descripción:', brecha['Description'])
    print('--------------------------------------------------')