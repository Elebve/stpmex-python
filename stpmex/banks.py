"""Compatibilidad SPEI sobre el catálogo de clabe-python."""
from typing import Dict

# Códigos que STP ya no acepta y su reemplazo actual.
INSTITUTION_CODE_ALIASES: Dict[str, str] = {
    '90638': '40638',  # Nu Sofipo -> Nubank
}


def resolve_institucion(code: str) -> str:
    return INSTITUTION_CODE_ALIASES.get(str(code), str(code))
