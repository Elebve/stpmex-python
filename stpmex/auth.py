from base64 import b64encode
from enum import Enum
from typing import List

from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.hazmat.primitives.hashes import SHA256

from azure.identity import DefaultAzureCredential
from azure.keyvault.certificates import CertificateClient
from azure.keyvault.keys import KeyClient
from azure.keyvault.keys.crypto import (CryptographyClient,
                                        EncryptionAlgorithm,
                                        SignatureAlgorithm)
from azure.keyvault.secrets import SecretClient
import hashlib
import base64
import os
VAULT_URL = os.environ.get('VAULT_URL')


import logging
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


def join_fields(obj: 'Resource', fieldnames: List[str]) -> bytes:  # noqa: F821
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


def compute_signature(STP_KEY: str, text: str) -> str:
    credential = DefaultAzureCredential()
    key_client = KeyClient(
        vault_url=VAULT_URL,
        credential=credential
        )
    key = key_client.get_key(STP_KEY)
    crypto_client = CryptographyClient(key, credential=credential)
    sha = hashlib.sha256(text.encode())
    digest = sha.digest()
    result = crypto_client.sign(SignatureAlgorithm.rs256, digest)
    digestValue = sha.hexdigest()
    signatureValue = result.signature
    signature_text = str(base64.b64encode(signatureValue).decode())
    return signature_text 
            
    # signature = pkey.sign(
    #     text.encode('utf-8'),
    #     padding.PKCS1v15(),
    #     SHA256(),
    # )
    # return b64encode(signature).decode('ascii')
