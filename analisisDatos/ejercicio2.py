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
print(f"Nº Dispositivos: {devices_df.__len__()}")
devices_df.replace(to_replace=["NULL"], value=nan, inplace=True)
print(f"Nº total de campos missing o None: {devices_df.isna().sum().sum()}")
print(f"Nº total de campos: {devices_df.isna().count().sum()}")
print(f"Nº campos que NO son missing/None: {devices_df.count().sum()}")


###########################################################
# B) NUMERO DE ALERTAS
###########################################################

alerts_df = pd.read_sql_query("SELECT * FROM alerts", conexion)
print(f"Nº alertas: {alerts_df['timestamp'].count()}")

###########################################################
# C) MEDIANA Y MODA DEL TOTAL DE PUERTOS ABIERTOS
###########################################################

# Primero guardaremos la columna de puertos abiertos sustituyendo los valores vacios.
puertosAbiertos = pd.read_sql_query("SELECT analisisPuertosAbiertos as puertosAbiertos FROM devices", conexion)
puertosAbiertos.replace(to_replace=["NULL"], value=np.nan, inplace=True)

# Ahora obtendremos el numero de puertos por registro. Haremos uso de Regez para identificar los puertos
puertosAbiertos['num_puertos'] = puertosAbiertos['puertosAbiertos'].fillna('').apply(lambda x: len(re.findall(r'\d+', str(x))))

# Vamos a calcular cuántas veces aparece cada puerto


print("hola1")
print(puertosAbiertos['num_puertos'])
print("hola2")
print(puertosAbiertos['puertosAbiertos'])
print(f"Mediana de puertos abiertos: {puertosAbiertos['num_puertos'].median():.2f}")
print(f"Moda de puertos abiertos: {puertosAbiertos['num_puertos'].mode():.2f}")


###########################################################
# D) MEDIANA Y MODA DEL Nº SERVICIOS INSEGUROS
###########################################################
print(devices_df['analisisServicios'])
print(f"Mediana de servicios inseguros detectados: {devices_df['analisisServicios'].median():.2f}")
print(f"Moda de servicios inseguros detectados: {devices_df['analisisServicios'].mode()}")

###########################################################
# E) MEDIANA Y MODA DEL Nº VULNERABILIDADES
###########################################################

print(f"Mediana de vulnerabilidades detectadas: {devices_df['analisisVulnerabilidades'].median():.2f}")
print(f"Moda de vulnerabilidades detectadas: {devices_df['analisisVulnerabilidades'].mode()}")

###########################################################
# F) MIN. Y MAX. DEL TOTAL DE PUERTOS ABIERTOS
###########################################################

print(f"Valor minimo total de la cantidad de puertos abiertos: {puertosAbiertos['num_puertos'].min()}")
print(f"Valor maximo total de la cantidad de puertos abiertos: {puertosAbiertos['num_puertos'].max()}")

###########################################################
# G) MIN. Y MAX. DEL TOTAL DE VULNERABILIDADES DETECTADAS
###########################################################

print(f"Valor minimo de vulnerabilidades detectadas: {devices_df['analisisVulnerabilidades'].min()}")
print(f"Valor maximo de vulnerabilidades detectadas: {devices_df['analisisVulnerabilidades'].max()}")