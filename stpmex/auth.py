import base64
import hashlib
import logging
import os
from enum import Enum
from typing import List, Union

from azure.identity import DefaultAzureCredential
from azure.keyvault.keys import KeyClient
from azure.keyvault.keys.crypto import CryptographyClient, SignatureAlgorithm
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.hazmat.primitives.hashes import SHA256

VAULT_URL = os.environ.get('VAULT_URL')


CUENTA_FIELDNAMES = """
    empresa
    cuenta
    rfcCurp
""".split()


ORDEN_FIELDNAMES = """
    institucionContraparte
    empresa
    fechaOperacion
    folioOrigen
    claveRastreo
    institucionOperante
    monto
    tipoPago
    tipoCuentaOrdenante
    nombreOrdenante
    cuentaOrdenante
    rfcCurpOrdenante
    tipoCuentaBeneficiario
    nombreBeneficiario
    cuentaBeneficiario
    rfcCurpBeneficiario
    emailBeneficiario
    tipoCuentaBeneficiario2
    nombreBeneficiario2
    cuentaBeneficiario2
    rfcCurpBeneficiario2
    conceptoPago
    conceptoPago2
    claveCatUsuario1
    claveCatUsuario2
    clavePago
    referenciaCobranza
    referenciaNumerica
    tipoOperacion
    topologia
    usuario
    medioEntrega
    prioridad
    iva
    """.split()
SIGN_DIGEST = 'RSA-SHA256'


def join_fields(obj: 'Resource', fieldnames: List[str]) -> str:  # noqa: F821
    joined_fields = []
    for field in fieldnames:
        value = getattr(obj, field, None)
        if isinstance(value, float):
            value = f'{value:.2f}'
        elif isinstance(value, Enum) and value:
            value = value.value
        elif value is None:
            value = ''
        joined_fields.append(str(value))
    output = '||' + '|'.join(joined_fields) + '||'
    logging.debug(f'join_fields output {output}')
    return output


def compute_signature(
    text: str, key: Union[str, RSAPrivateKey, None] = None
) -> str:
    if isinstance(key, RSAPrivateKey):
        signature = key.sign(
            text.encode('utf-8'),
            padding.PKCS1v15(),
            SHA256(),
        )
        return base64.b64encode(signature).decode('ascii')
    return _sign_with_azure(text, key or os.environ.get('STP_KEY'))


def _sign_with_azure(text: str, stp_key: str) -> str:
    credential = DefaultAzureCredential()
    key_client = KeyClient(vault_url=VAULT_URL, credential=credential)
    key = key_client.get_key(stp_key)
    crypto_client = CryptographyClient(key, credential=credential)
    digest = hashlib.sha256(text.encode()).digest()
    result = crypto_client.sign(SignatureAlgorithm.rs256, digest)
    return str(base64.b64encode(result.signature).decode())
