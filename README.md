# STP python3.9+ client library


Cliente REST de STP (fork de Atria). El catálogo de bancos sale de
[Elebve/clabe-python](https://github.com/Elebve/clabe-python).


## Requerimientos

Python 3.9 o superior.

## Documentación de API

[General](https://stpmex.zendesk.com/hc/es) y
[WADL](https://demo.stpmex.com:7024/speiws/rest/application.wadl?metadata=true&detail=true)

## Instalación

```
pip install git+https://github.com/Elebve/stpmex-python.git
```

Esto instala también el fork de CLABE con el catálogo actualizado de Banxico
(Nubank `40638`, etc.).

## Firma

Por defecto Atria firma con Azure Key Vault. Define `VAULT_URL` y el nombre
de la llave en `STP_KEY`:

```python
from stpmex import Client

client = Client(empresa='TU_EMPRESA')  # STP_KEY sale del entorno
```

También puedes firmar con un PEM local (útil en pruebas):

```python
client = Client(
    empresa='TU_EMPRESA',
    STP_KEY=pem,
    passphrase='tu-passphrase',
    demo=True,
)
```

El código de institución legado `90638` (Nu Sofipo) se envía como `40638`
(Nubank), que es el que STP acepta hoy.

## Correr pruebas

```
make venv
source venv/bin/activate
make test
```

## Uso básico

```python
import datetime as dt

from stpmex import Client
from stpmex.types import Pais

client = Client(
    empresa='TU_EMPRESA',
)

cuenta_persona_fisica = client.cuentas.alta(
    nombre='Eduardo',
    apellidoPaterno='Salvador',
    apellidoMaterno='Hernández',
    rfcCurp='SAHE800416HDFABC01',
    cuenta='646180110400000007',
    paisNacimiento=Pais.MX,
    fechaNacimiento=dt.date(1980, 4, 14),
)


cuenta_persona_moral = client.cuentas_morales.alta(
    nombre='LA TIENDITA DE LA ESQUINA SA DE CV',
    cuenta='646180157036325892',
    pais=Pais.MX,
    fechaConstitucion=dt.date(2021, 1, 1),
    rfcCurp='ABC200101AB0',
)

# Si deseas dar de alta una nueva clabe para la misma
# razón social, haces el mismo request sustituyendo `cuenta`
# con la nueva clabe
cuenta_persona_moral = client.cuentas_morales.alta(
    nombre='LA TIENDITA DE LA ESQUINA SA DE CV',
    cuenta='646180157036325832',
    pais=Pais.MX,
    fechaConstitucion=dt.date(2021, 1, 1),
    rfcCurp='ABC200101AB0',
)

orden = client.ordenes.registra(
    monto=1.2,
    cuentaOrdenante=cuenta_persona_fisica.cuenta,
    nombreBeneficiario='Ricardo Sanchez',
    cuentaBeneficiario='072691004495711499',
    institucionContraparte='40072',
    conceptoPago='Prueba',
)

# Saldo
saldo = client.saldos.consulta(cuenta='646456789123456789')

# Ordenes - enviadas
enviadas = client.ordenes.consulta_enviadas()  # fecha_operacion es el día de hoy

# Ordenes - recibidas
recibidas = client.ordenes.consulta_recibidas(
    fecha_operacion=dt.date(2020, 4, 20)
)

# Orden - consulta por clave rastreo
orden = client.ordenes.consulta_clave_rastreo(
    claveRastreo='CR1234567890',
    institucionOperante=90646,
    fechaOperacion=dt.date(2020, 4, 20)
)
```
