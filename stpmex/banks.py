"""
Catálogo SPEI alineado con Banxico y cuenca-mx/clabe-python.

Fuente: https://www.banxico.org.mx/cep-scl/listaInstituciones.do
"""
import importlib
from typing import Dict, Iterable, Tuple

# Prefijo CLABE (3) -> código Banxico (5)
BANKS: Dict[str, str] = {
    '138': '40138',
    '133': '40133',
    '062': '40062',
    '638': '40638',
    '706': '90706',
    '659': '90659',
    '128': '40128',
    '127': '40127',
    '166': '37166',
    '030': '40030',
    '002': '40002',
    '154': '40154',
    '006': '37006',
    '137': '40137',
    '160': '40160',
    '152': '40152',
    '019': '37019',
    '147': '40147',
    '106': '40106',
    '159': '40159',
    '009': '37009',
    '072': '40072',
    '058': '40058',
    '060': '40060',
    '001': '2001',
    '129': '40129',
    '145': '40145',
    '012': '40012',
    '112': '40112',
    '677': '90677',
    '683': '90683',
    '630': '90630',
    '124': '40124',
    '143': '40143',
    '631': '90631',
    '901': '90901',
    '903': '90903',
    '130': '40130',
    '140': '40140',
    '725': '90725',
    '652': '90652',
    '688': '90688',
    '680': '90680',
    '723': '90723',
    '729': '90729',
    '722': '90722',
    '720': '90720',
    '151': '40151',
    '616': '90616',
    '634': '90634',
    '689': '90689',
    '699': '90699',
    '685': '90685',
    '601': '90601',
    '168': '37168',
    '021': '40021',
    '155': '40155',
    '036': '40036',
    '902': '90902',
    '150': '40150',
    '136': '40136',
    '059': '40059',
    '110': '40110',
    '661': '90661',
    '653': '90653',
    '670': '90670',
    '602': '90602',
    '042': '40042',
    '158': '40158',
    '600': '90600',
    '108': '40108',
    '132': '40132',
    '135': '37135',
    '710': '90710',
    '684': '90684',
    '148': '40148',
    '620': '90620',
    '156': '40156',
    '014': '40014',
    '044': '40044',
    '157': '40157',
    '728': '90728',
    '646': '90646',
    '730': '90730',
    '656': '90656',
    '617': '90617',
    '605': '90605',
    '703': '90703',
    '113': '40113',
    '141': '40141',
    '715': '90715',
    '732': '90732',
    '714': '90714',
    '734': '90734',
    '167': '40167',
    '721': '90721',
    '727': '90727',
    '738': '90738',
    '170': '40170',
    '660': '90660',
}

BANK_NAMES: Dict[str, str] = {
    '40133': 'Actinver',
    '40062': 'Afirme',
    '90721': 'Albo',
    '90660': 'Altor',
    '90706': 'Arcus Fi',
    '90659': 'Asp Integra Opc',
    '40128': 'Kapital',
    '40127': 'Azteca',
    '37166': 'BaBien',
    '40030': 'Bajio',
    '40002': 'Banamex',
    '40154': 'Banco Covalto',
    '37006': 'Bancomext',
    '40137': 'Bancoppel',
    '40160': 'Banco S3',
    '40152': 'Bancrea',
    '37019': 'Banjercito',
    '40147': 'Bankaool',
    '40106': 'Bank Of America',
    '40159': 'Bank Of China',
    '37009': 'Banobras',
    '40072': 'Banorte',
    '40058': 'Banregio',
    '40060': 'Bansi',
    '2001': 'Banxico',
    '40129': 'Barclays',
    '40145': 'BBase',
    '40012': 'BBVA Mexico',
    '40112': 'Bmonex',
    '90677': 'Caja Pop Mexica',
    '90683': 'Caja Telefonist',
    '90715': 'Cashi Cuenta',
    '90630': 'CB Intercam',
    '40124': 'Citi Mexico',
    '40143': 'CIBanco',
    '90631': 'TRF',
    '90901': 'Cls',
    '90903': 'CoDi Valida',
    '40130': 'Compartamos',
    '40140': 'Consubanco',
    '90725': 'COOPDESARROLLO',
    '90652': 'Credicapital',
    '90688': 'Crediclub',
    '90680': 'Cristobal Colon',
    '90723': 'Cuenca',
    '90729': 'Dep y Pag Dig',
    '40151': 'Donde',
    '90616': 'Finamex',
    '90634': 'Fincomun',
    '90734': 'Finco Pay',
    '90738': 'Fintoc',
    '90689': 'Fomped',
    '90699': 'Fondeadora',
    '90685': 'Fondo (Fira)',
    '90601': 'Gbm',
    '40167': 'Hey Banco',
    '37168': 'Hipotecaria Fed',
    '40021': 'HSBC',
    '40155': 'Icbc',
    '40036': 'Inbursa',
    '90902': 'Indeval',
    '40150': 'Inmobiliario',
    '40136': 'Intercam Banco',
    '40059': 'Invex',
    '40110': 'JP Morgan',
    '90661': 'KLAR',
    '90653': 'Kuspit',
    '90670': 'Libertad',
    '90602': 'Masari',
    '90722': 'Mercado Pago W',
    '90720': 'MexPago',
    '40042': 'Mifel',
    '40158': 'Mizuho Bank',
    '90600': 'Monexcb',
    '40108': 'Mufg',
    '40132': 'Multiva Banco',
    '37135': 'Nafin',
    '40638': 'NUBANK',
    '90710': 'NVIO',
    '40148': 'Pagatodo',
    '90732': 'Peibo',
    '90714': 'PPBALANCEMX',
    '90620': 'Profuturo',
    '40170': 'Revolut Bank',
    '40156': 'Sabadell',
    '40014': 'Santander',
    '40044': 'Scotiabank',
    '40157': 'Shinhan',
    '90728': 'Spin by OXXO',
    '90646': 'STP',
    '90730': 'Clip',
    '90703': 'Tesored',
    '90684': 'Transfer',
    '90727': 'Transfer directo',
    '40138': 'Uala',
    '90656': 'Unagra',
    '90617': 'Valmex',
    '90605': 'Value',
    '40113': 'Ve Por Mas',
    '40141': 'Volkswagen',
}

# Códigos que STP ya no acepta y su reemplazo actual.
INSTITUTION_CODE_ALIASES: Dict[str, str] = {
    '90638': '40638',  # Nu Sofipo -> Nubank
}

OBSOLETE_SPEI_CODES = frozenset(INSTITUTION_CODE_ALIASES)

_CLABE_MODULES = (
    'clabe',
    'clabe.banks',
    'clabe.validations',
    'clabe.types',
)


def resolve_institucion(code: str) -> str:
    return INSTITUTION_CODE_ALIASES.get(str(code), str(code))


def _iter_clabe_dicts() -> Iterable[Tuple[str, dict]]:
    seen = set()
    for module_name in _CLABE_MODULES:
        try:
            module = importlib.import_module(module_name)
        except ImportError:
            continue
        for attr in ('BANKS', 'BANK_NAMES'):
            mapping = getattr(module, attr, None)
            if not isinstance(mapping, dict):
                continue
            mapping_id = id(mapping)
            if mapping_id in seen:
                continue
            seen.add(mapping_id)
            yield attr, mapping


def sync_clabe_catalog() -> None:
    """Actualiza el catálogo en memoria de `clabe` sin exigir clabe 2.x."""
    for attr, mapping in _iter_clabe_dicts():
        if attr == 'BANKS':
            for prefix, code in list(mapping.items()):
                if code in OBSOLETE_SPEI_CODES:
                    mapping.pop(prefix, None)
            mapping.update(BANKS)
        else:
            for code in OBSOLETE_SPEI_CODES:
                mapping.pop(code, None)
            mapping.update(BANK_NAMES)


sync_clabe_catalog()
