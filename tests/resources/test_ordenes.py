import datetime as dt
import time
from typing import Any, Dict
from unittest.mock import patch

import pytest
from pydantic import ValidationError

from stpmex import Client
from stpmex.exc import NoOrdenesEncontradas
from stpmex.resources import Orden
from stpmex.types import TipoCuenta


@pytest.mark.vcr
def test_registra_orden(client: Client, orden_dict: Dict[str, Any]):
    orden_dict['claveRastreo'] = f'CR{int(time.time())}'
    orden = client.ordenes.registra(**orden_dict)
    assert isinstance(orden.id, int)


@pytest.mark.parametrize(
    'cuenta, tipo',
    [
        ('072691004495711499', TipoCuenta.clabe),
        ('4000000000000002', TipoCuenta.card),
        ('5512345678', TipoCuenta.phone_number),
        ('123', None),
    ],
)
def test_tipoCuentaBeneficiario(cuenta: str, tipo: TipoCuenta):
    assert Orden.get_tipo_cuenta(cuenta) == tipo


@pytest.mark.parametrize('monto', [-1.3, 1])
def test_strict_pos_float(monto, orden_dict: Dict[str, Any]):
    orden_dict['claveRastreo'] = f'CR{int(time.time())}'
    orden_dict['monto'] = monto

    with pytest.raises(ValidationError):
        Orden(**orden_dict)


@pytest.mark.vcr
def test_consulta_ordenes_enviadas(client):
    enviadas = client.ordenes.consulta_enviadas()
    assert len(enviadas) > 0


@pytest.mark.vcr
def test_consulta_ordenes_recibidas(client):
    recibidas = client.ordenes.consulta_recibidas()
    assert len(recibidas) > 0


@pytest.mark.vcr
def test_consulta_ordenes_enviadas_con_fecha(client):
    enviadas = client.ordenes.consulta_enviadas(dt.date(2020, 4, 20))
    assert len(enviadas) > 0


@pytest.mark.vcr
def test_consulta_ordenes_enviadas_con_fecha_sin_resultados(client):
    enviadas = client.ordenes.consulta_enviadas(dt.date(2021, 4, 20))
    assert len(enviadas) == 0


@pytest.mark.vcr
def test_consulta_orden_por_clave_rastreo(client):
    orden = client.ordenes.consulta_clave_rastreo(
        'CR1564969083', 90646, dt.date(2020, 4, 20)
    )
    assert orden.claveRastreo == 'CR1564969083'


@pytest.mark.vcr
def test_consulta_orden_por_clave_rastreo_recibida(client):
    orden = client.ordenes.consulta_clave_rastreo(
        'CR1564969083', 40072, dt.date(2020, 4, 20)
    )
    assert orden.claveRastreo == 'CR1564969083'


@pytest.mark.vcr
def test_consulta_orden_sin_resultado(client):
    with pytest.raises(NoOrdenesEncontradas):
        client.ordenes.consulta_clave_rastreo(
            'does not exist', 90646, dt.date(2020, 4, 20)
        )


@pytest.mark.vcr
def test_consulta_orden_sin_resultado_recibida(client):
    with pytest.raises(NoOrdenesEncontradas):
        client.ordenes.consulta_clave_rastreo(
            'does not exist', 40072, dt.date(2020, 4, 20)
        )


@patch('stpmex.types.BLOCKED_INSTITUTIONS', {'90659'})
def test_institucion_bloqueada_no_permite_registrar_orden(
    client: Client, orden_dict: Dict[str, Any]
):
    orden_dict['cuentaBeneficiario'] = '659802025000339321'
    with pytest.raises(ValidationError) as exc:
        client.ordenes.registra(**orden_dict)

    assert any(
        error['loc'][0] == 'cuentaBeneficiario'
        and error['type'] == 'clabe.bank_code'
        for error in exc.value.errors()
    )
