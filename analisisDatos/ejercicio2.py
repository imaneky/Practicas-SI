import sqlite3
import pandas as pd
import numpy as np
import re
from numpy import nan

conexion = sqlite3.connect('alerts_database.db')
c = conexion.cursor()

###########################################################
# A) NUMERO DE DISPOISITVIOS Y CAMPOS NONE
###########################################################

devices_df = pd.read_sql_query("SELECT * FROM devices", conexion)
print(f"Nº Dispositivos: {len(devices_df)}")
devices_df.replace(to_replace=["NULL"], value=nan, inplace=True)
print(f"Nº total de campos missing o None: {devices_df.isna().sum().sum()}")
print(f"Nº total de campos: {devices_df.isna().count().sum()}")
print(f"Nº campos que NO son missing/None: {devices_df.count().sum()}")
print("\n")

###########################################################
# B) NUMERO DE ALERTAS
###########################################################

alerts_df = pd.read_sql_query("SELECT * FROM alerts", conexion)
print(f"Nº alertas: {alerts_df['timestamp'].count()}")
print("\n")

###########################################################
# C) MEDIANA Y MODA DEL TOTAL DE PUERTOS ABIERTOS
###########################################################

# Primero guardaremos la columna de puertos abiertos sustituyendo los valores vacios
puertosAbiertos = pd.read_sql_query("SELECT analisisPuertosAbiertos as puertosAbiertos FROM devices", conexion)
puertosAbiertos.replace(to_replace=["NULL"], value=np.nan, inplace=True)

# Para calcular la mediana, nos conviene saber el numero de puertos por dispositivo. Nos ayudaremos de las expresiones regulares
puertosAbiertos['num_puertos'] = puertosAbiertos['puertosAbiertos'].fillna('').apply(lambda x: len(re.findall(r'\d+', str(x))))

# Para la moda, primero obtendremos la lista de puertos abiertos
puertos = puertosAbiertos['puertosAbiertos'].dropna().tolist()
puertos_concatenados = ''.join(puertos)

# Utilizamos una expresión regular para extraer los puertos individuales
puertos_individuales = re.findall(r'\d+', puertos_concatenados)

# Calculamos la frecuencia de cada puerto
puertos_frecuencia = pd.Series(puertos_individuales).value_counts()

# Obtener el puerto con mayor número de repeticiones
mayor_repeticion = puertos_frecuencia.idxmax()
repeticiones_maximas = puertos_frecuencia[mayor_repeticion]

# En este caso, hemos ententendido del enunciado que la moda de los puertos abiertos es el puerto que más se repite,
# y no el dispositivo que más puertos tiene

print(f"Mediana de puertos abiertos: {puertosAbiertos['num_puertos'].median():.2f}")
print("Moda de puertos abiertos: ", repeticiones_maximas, "del puerto ", mayor_repeticion)
print("\n")

###########################################################
# D) MEDIANA Y MODA DEL Nº SERVICIOS INSEGUROS
###########################################################
analisis_servicios_inseguros = devices_df['analisisServiviosInseguros']
servicio_inseguro_frecuencia = analisis_servicios_inseguros.value_counts()
servicio_mas_frecuente = servicio_inseguro_frecuencia.idxmax()
num_repeticiones = servicio_inseguro_frecuencia[servicio_mas_frecuente]

print(f"Mediana de servicios inseguros detectados: {analisis_servicios_inseguros.median():.2f}")
print(f"Moda de servicios inseguros detectados:", servicio_mas_frecuente, "que se repite un total de", num_repeticiones, "veces")
print(analisis_servicios_inseguros)
print("\n")

###########################################################
# E) MEDIANA Y MODA DEL Nº VULNERABILIDADES
###########################################################

analisis_vulnerabilidades = devices_df['analisisVulnerabilidades']
print(f"Mediana de vulnerabilidades detectadas: {analisis_vulnerabilidades.median():.2f}")
print(f"No podemos concluir la moda para este caso, ya que todos los valores se repiten el mismo nº de veces."
      f"Estamos ante un caso multimodal:", np.unique(analisis_vulnerabilidades))
print("\n")

###########################################################
# F) MIN. Y MAX. DEL TOTAL DE PUERTOS ABIERTOS
###########################################################

print(f"Valor mínimo total de la cantidad de puertos abiertos: {puertosAbiertos['num_puertos'].min()}")
print(f"Valor máximo total de la cantidad de puertos abiertos: {puertosAbiertos['num_puertos'].max()}")
print("\n")

###########################################################
# G) MIN. Y MAX. DEL TOTAL DE VULNERABILIDADES DETECTADAS
###########################################################

print(f"Valor mínimo de vulnerabilidades detectadas: {devices_df['analisisVulnerabilidades'].min()}")
print(f"Valor máximo de vulnerabilidades detectadas: {devices_df['analisisVulnerabilidades'].max()}")

conexion.close()