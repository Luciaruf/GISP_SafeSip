# definiamo l'algoritmo per il calcolo del bac 

from datetime import datetime, timedelta
from typing import Dict, List, Tuple, Union, Optional

# Constants
WIDMARK_CONSTANTS = {
    'MALE_R': 0.68,      # Fattore di distribuzione per uomini
    'FEMALE_R': 0.55,    # Fattore di distribuzione per donne
    'BETA': 0.15,        # Tasso di eliminazione dell'alcol (g/l per ora)
    'ALCOHOL_DENSITY': 0.789  # Densità dell'alcol etilico in g/ml
}

STOMACH_FACTORS = {
    'vuoto': 1.0,
    'pieno': 0.7
}

BAC_THRESHOLDS = {
    'SOBER': 0.3,
    'WARNING': 0.45,
    'LEGAL_LIMIT': 0.5
}

def calcola_tasso_alcolemico_widmark(
    peso: float,
    genere: str,
    volume: float,
    gradazione: float,
    stomaco: str,
    ora_inizio: str,
    ora_fine: str
) -> float:
    """
    Calcola il tasso alcolemico usando la formula di Widmark per una singola bevanda.
    
    Args:
        peso: Peso in kg
        genere: 'uomo' o 'donna'
        volume: Volume della bevanda in ml
        gradazione: Gradazione alcolica in percentuale (es. 0.12)
        stomaco: 'pieno' o 'vuoto'
        ora_inizio: Ora di inizio consumo nel formato 'HH:MM'
        ora_fine: Ora di fine consumo nel formato 'HH:MM'
    
    Returns:
        Tasso alcolemico in g/l
    """
    # Seleziona il fattore di distribuzione in base al genere
    r = WIDMARK_CONSTANTS['MALE_R'] if genere == 'uomo' else WIDMARK_CONSTANTS['FEMALE_R']
    
    # Calcolo del tempo di consumo in ore
    inizio = datetime.strptime(ora_inizio, '%H:%M')
    fine = datetime.strptime(ora_fine, '%H:%M')
    if fine < inizio:  # Se il consumo passa la mezzanotte
        fine = fine + timedelta(days=1)
    tempo_consumazione = (fine - inizio).total_seconds() / 3600
    
    # Calcolo grammi di alcol puro
    volume_alcol_ml = volume * gradazione
    grammi_alcol = volume_alcol_ml * WIDMARK_CONSTANTS['ALCOHOL_DENSITY']
    
    # Fattore di assorbimento basato sullo stato dello stomaco
    assorbimento = STOMACH_FACTORS.get(stomaco.lower(), 1.0)
    
    # Calcolo BAC usando la formula di Widmark
    bac = (grammi_alcol * assorbimento) / (peso * r) - (WIDMARK_CONSTANTS['BETA'] * tempo_consumazione)
    
    return round(max(0, bac), 3)

def calcola_alcol_metabolizzato(bac: float, tempo_ore: float) -> float:
    """
    Calcola quanto alcol è stato metabolizzato in un determinato periodo di tempo.
    
    Args:
        bac: Tasso alcolemico iniziale in g/l
        tempo_ore: Tempo trascorso in ore
    
    Returns:
        Tasso alcolemico dopo il metabolismo
    """
    alcol_metabolizzato = WIDMARK_CONSTANTS['BETA'] * tempo_ore
    return round(max(0, bac - alcol_metabolizzato), 3)

def calcola_tempo_trascorso(ora_inizio: str, ora_fine: str) -> Tuple[float, str]:
    """
    Calcola il tempo trascorso tra due orari.
    
    Args:
        ora_inizio: Ora di inizio nel formato 'HH:MM'
        ora_fine: Ora di fine nel formato 'HH:MM'
    
    Returns:
        Tuple contenente (tempo_trascorso, unità_misura)
    """
    inizio = datetime.strptime(ora_inizio, '%H:%M')
    fine = datetime.strptime(ora_fine, '%H:%M')
    if fine < inizio:  # Se il tempo passa la mezzanotte
        fine = fine + timedelta(days=1)
    
    tempo_ore = (fine - inizio).total_seconds() / 3600
    
    if tempo_ore < 1:
        return round(tempo_ore * 60), 'minuti'
    return round(tempo_ore, 2), 'ore'

def calcola_bac_cumulativo(
    peso: float,
    genere: str,
    lista_bevande: List[Dict[str, Union[float, str]]],
    stomaco: str
) -> Dict[str, Union[float, List[Dict[str, Union[float, str]]]]]:
    """
    Calcola il tasso alcolemico cumulativo per una lista di bevande.
    
    Args:
        peso: Peso in kg
        genere: 'uomo' o 'donna'
        lista_bevande: Lista di dizionari contenenti le informazioni delle bevande
        stomaco: 'pieno' o 'vuoto'
    
    Returns:
        Dizionario contenente il BAC finale e la storia del metabolismo
    """
    bac_totale = 0.0
    storia_metabolismo = []
    
    for i, bevanda in enumerate(lista_bevande):
        if i > 0:
            bevanda_precedente = lista_bevande[i-1]
            tempo_trascorso, unità = calcola_tempo_trascorso(
                bevanda_precedente['ora_fine'],
                bevanda['ora_inizio']
            )
            tempo_ore = tempo_trascorso / 60 if unità == 'minuti' else tempo_trascorso
            
            bac_totale += calcola_tasso_alcolemico_widmark(
                peso, genere,
                bevanda_precedente['volume'],
                bevanda_precedente['gradazione'],
                stomaco,
                bevanda_precedente['ora_fine'],
                bevanda_precedente['ora_inizio']
            )
            
            storia_metabolismo.append({
                'tempo_trascorso': tempo_trascorso,
                'unità': unità,
                'bac_dopo_metabolismo': bac_totale
            })
        
        bac_totale += calcola_tasso_alcolemico_widmark(
            peso=peso,
            genere=genere,
            volume=bevanda['volume'],
            gradazione=bevanda['gradazione'],
            stomaco=stomaco,
            ora_inizio=bevanda['ora_inizio'],
            ora_fine=bevanda['ora_fine']
        )
    
    return {
        'bac_finale': bac_totale,
        'storia_metabolismo': storia_metabolismo
    }

def interpreta_tasso_alcolemico(bac: float) -> Dict[str, Union[str, bool]]:
    """
    Interpreta il tasso alcolemico e fornisce informazioni sulla legalità.
    
    Args:
        bac: Tasso alcolemico in g/l
    
    Returns:
        Dizionario con interpretazione e livello legale
    """
    if bac == 0:
        return {'livello': 'Astemio', 'legale': True}
    elif bac < BAC_THRESHOLDS['SOBER']:
        return {'livello': 'Sobrio', 'legale': True}
    elif bac < BAC_THRESHOLDS['WARNING']:
        return {'livello': 'Vicino al limite', 'legale': True}
    elif bac <= BAC_THRESHOLDS['LEGAL_LIMIT']:
        return {'livello': 'Limite superato', 'legale': True}
    else:
        return {'livello': 'Limite superato', 'legale': False}

def calcola_tempo_sober(bac: float) -> str:
    """
    Calcola il tempo stimato necessario per tornare sobri.
    
    Args:
        bac: Tasso alcolemico attuale in g/l
    
    Returns:
        Tempo stimato in ore o minuti
    """
    tempo_ore = bac / WIDMARK_CONSTANTS['BETA']
    
    if tempo_ore < 1:
        return f"{round(tempo_ore * 60)} minuti"
    return f"{round(tempo_ore, 1)} ore"

# Test code
if __name__ == "__main__":
    test_bevande = [
        {
            'volume': 100,
            'gradazione': 0.12,
            'ora_inizio': '20:00',
            'ora_fine': '20:05'
        },
        {
            'volume': 200,
            'gradazione': 0.12,
            'ora_inizio': '20:30',
            'ora_fine': '21:00'
        }
    ]
    
    risultato = calcola_bac_cumulativo(
        peso=70,
        genere='uomo',
        lista_bevande=test_bevande,
        stomaco='pieno'
    )
    
    print(f"\nTasso alcolemico finale: {risultato['bac_finale']} g/l")
    
    print("\nStoria del metabolismo:")
    for i, metabolismo in enumerate(risultato['storia_metabolismo']):
        print(f"Tra il drink {i+1} e {i+2}:")
        print(f"  Tempo trascorso: {metabolismo['tempo_trascorso']} {metabolismo['unità']}")
        print(f"  BAC dopo metabolismo: {metabolismo['bac_dopo_metabolismo']} g/l")
    
    interpretazione = interpreta_tasso_alcolemico(risultato['bac_finale'])
    print(f"\nInterpretazione:")
    print(f"Livello: {interpretazione['livello']}")
    print(f"Legale: {'Sì' if interpretazione['legale'] else 'No'}")
    
    tempo_sober = calcola_tempo_sober(risultato['bac_finale'])
    print(f"\nTempo stimato per tornare sobri: {tempo_sober}")
