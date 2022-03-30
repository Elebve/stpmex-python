import datetime as dt
import pytest
from clabe import generate_new_clabes

from stpmex.resources import CuentaFisica

from stpmex.types import Pais, EntidadFederativa, ActividadEconomica


@pytest.mark.vcr
def test_alta_cuenta(client, cuenta_dict):
    cuenta = client.cuentas.alta(**cuenta_dict)
    assert cuenta


@pytest.mark.vcr
def test_baja_cuenta(client, cuenta):
    assert cuenta.baja()


@pytest.mark.vcr
@pytest.mark.parametrize('num_cuentas', [95, 450])
def test_alta_lote(client, cuenta_dict, num_cuentas):
    del cuenta_dict['cuenta']
    clabes = generate_new_clabes(num_cuentas, '6461801570')

    lote = []
    for clabe in clabes:
        cuenta = CuentaFisica(**cuenta_dict, cuenta=clabe)
        lote.append(cuenta)
    resp = client.cuentas.alta_lote(lote)
    assert list(resp.keys()) == clabes
    assert all(r['id'] == 0 for r in resp.values())
    assert all(
        r['descripcion'] == 'Cuenta en revisión.' for r in resp.values()
    )
    for cuenta in lote:
        cuenta.baja()


def test_cuenta_nombre_apellidos_correctos(cuenta):
    assert cuenta.nombre == 'EDUARDO MARCO'
    assert cuenta.apellidoMaterno == 'HERNANDEZ MUNOZ'
    assert cuenta.apellidoPaterno == 'SALVADOR'


@pytest.mark.vcr
def test_alta_cuenta_persona_moral(client):
    cuenta_moral_dict = dict(
        nombre='Tarjetas Cuenca',
        empresa_='Tarjetas Cuenca',
        cuenta='646180157095835268',
        pais=Pais.MX,
        fechaConstitucion=dt.date(2021, 1, 1),
        rfcCurp='TCU200828RX8',
        entidadFederativa=EntidadFederativa.DF,
        actividadEconomica=ActividadEconomica.FINTECH_WALLET,
    )
    cuenta = client.cuentas_morales.alta(**cuenta_moral_dict)
    assert cuenta