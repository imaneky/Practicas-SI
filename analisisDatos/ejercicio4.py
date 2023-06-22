import re
import sqlite3
import numpy as np
import pandas as pd
from matplotlib import pyplot as plt
from numpy import nan

conexion = sqlite3.connect('alerts_database.db')
c = conexion.cursor()

alerts_df = pd.read_sql_query("SELECT * from alerts", conexion)
devices_df = pd.read_sql_query("SELECT * FROM devices", conexion)

# IP DE ORIGEN MAS PROBLEMATICAS

# Seleccionamos primero las alertas de prioridad 1
ip_p1_df = alerts_df[alerts_df['prioridad'] == 1]

# Ahora las agruparemos por ip y contaremos cuantas alertas hay con cada ip en una nueva columna
ip_p1_df = ip_p1_df.groupby('origen')['sid'].count().reset_index(name='numero_alertas')

# Ahora lo ordenaremos en orden descendente segun los valores de la columna 'numero_alertas'
ip_p1_df.sort_values(by=['numero_alertas'], ascending=False, inplace=True)

ip_p1_df.head(10).plot(title='Top 10 IPs mas problematicas', x='origen', y='numero_alertas', kind='bar', figsize=(15,12))
plt.xticks(rotation =45, ha='right', rotation_mode='anchor')
plt.xlabel('IP de origen')
plt.ylabel('Nº alertas')
plt.show()

# HISTOGRAMA - NUMERO DE ALERTAS EN EL TIEMPO

alertas_tiempo_df = alerts_df.groupby('timestamp')['sid'].count().reset_index(name='numero_alertas')
alertas_tiempo_df['timestamp'] = pd.to_datetime(alertas_tiempo_df['timestamp'], errors='coerce')
alertas_tiempo_df = alertas_tiempo_df.set_index('timestamp')
alertas_dia = alertas_tiempo_df.resample('D').sum()
plt.xticks(rotation=45, ha="right", rotation_mode="anchor")
plt.figure(figsize=(15,12))
plt.xlabel('Fecha')
plt.ylabel('Nº alertas')
plt.plot(alertas_dia.index, alertas_dia['numero_alertas'])
plt.show()


# PORCENTAJE DEL TOTAL DE NUMERO DE ALERTAS POR CATEGORIA - GRAFICO CIRCULAR

alertas_categoria_df = alerts_df.groupby('clasificacion')['clasificacion'].count().reset_index(name='numero_alertas')

# Obtener los datos de las categorias y los numeros de alertas
categorias = alertas_categoria_df['clasificacion']
num_alertas = alertas_categoria_df['numero_alertas']

# Calcular los porcentajes correspondientes a cada categoria
total_alertas = sum(num_alertas)
porcentajes = [(num / total_alertas) * 100 for num in num_alertas]
porcentajes_str = [f'{porcentaje:.2f}%' for porcentaje in porcentajes]

# Configurar el gráfico
fig, ax = plt.subplots(figsize=(10, 10))  # Ajustar el tamaño del gráfico
colors = plt.cm.Set3(range(len(categorias)))  # Colores para cada categoría
explode = [0.1] * len(categorias)  # Separación de los sectores del gráfico
wedges, texts, autotexts = ax.pie(num_alertas, labels=categorias, startangle=90, colors=colors, explode=explode,
                                 autopct='%1.1f%%', textprops={'fontsize': 'small'})
ax.axis('equal')
plt.title('Porcentaje alertas por categoría')

# Añadir leyenda
legend_labels = [f'{categoria}: {porcentaje}' for categoria, porcentaje in zip(categorias, porcentajes_str)]
plt.legend(wedges, legend_labels, loc='center left', bbox_to_anchor=(1, 0.5), title='Categorías y Porcentajes', fontsize='small')
plt.tight_layout() # Ajustar el espacio para evitar que los nombres se superpongan
plt.show()

# DISPOSITIVOS MAS VULNERABLES (SUMA SERVICIOS VULNERABLES Y VULNERABILIDADES DETECTADAS)

dispositivos_vulnerables_df = pd.read_sql_query('SELECT id, SUM(analisisServiviosInseguros + analisisVulnerabilidades) as num_vulnerabilidades FROM devices GROUP BY id ORDER BY num_vulnerabilidades', conexion)
vulnerabilidades = dispositivos_vulnerables_df['num_vulnerabilidades'].tolist()
etiquetas = dispositivos_vulnerables_df['id']
plt.bar(etiquetas, vulnerabilidades)
plt.xlabel('Dispositivos')
plt.ylabel('Nº vulnerabilidades')
plt.title('Vulnerabilidades + Servicios Inseguros por dispositivo')
plt.show()

# MEDIA DE PUERTOS ABIERTOS FRENTE A SERVICIOS INSEGUROS Y FRENTE AL TOTAL DE SERVICIOS DETECTADOS

puertos_abiertos_df = pd.read_sql_query('SELECT analisisPuertosAbiertos as puertos_abiertos from devices', conexion)
puertos_abiertos_df.replace(to_replace="NULL", value=np.nan, inplace=True)

puertos_abiertos_df['num_puertos'] = puertos_abiertos_df['puertos_abiertos'].fillna('').apply(lambda x: len(re.findall(r'\d+', str(x))))
media_puertos_abiertos = puertos_abiertos_df['num_puertos'].mean()

servicios_inseguros = sum(devices_df['analisisServiviosInseguros'])
servicios = sum(devices_df['analisisServicios'])

servicios_inseguros_puertos = int((media_puertos_abiertos/servicios_inseguros)*100)
servicios_puertos = int((media_puertos_abiertos/servicios)*100)

porcentajes = ['Media Puertos Servicios Inseguros', 'Media Puertos Servicios']
elementos = [servicios_inseguros_puertos, servicios_puertos]
plt.bar(porcentajes, elementos, color=['pink', 'purple'])
plt.title("Comparativa")
plt.show()
conexion.close()