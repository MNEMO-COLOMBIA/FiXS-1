# FiXS-1
Esta regla busca la presencia de archivos con nombres o hashes asociados con FiXS, y también se asegura de que el tamaño del archivo sea menor de 200KB.
Si se encuentra un archivo que coincide con cualquiera de las condiciones mencionadas anteriormente, la regla se activará y se generará una alerta.
Este comando escaneará el directorio especificado en "la ruta donde guarde la regla Yara" y buscará archivos maliciosos que coincidan con esta regla YARA 
Si se encuentra un archivo que coincide con la regla, se generará una alerta que indicará que se ha detectado FiXS en el sistema.
