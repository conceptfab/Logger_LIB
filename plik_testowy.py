#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Skrypt testowy dla biblioteki Logger_LIB w wersji 0.2x
Testuje funkcjonalności oferowane przez Logger przy obecnym poziomie logowania.

Użycie:
1. Przed uruchomieniem ustaw odpowiedni poziom logowania poprzez utworzenie pliku:
   - Utwórz pusty plik w katalogu core/ o nazwie:
     - INFO - dla podstawowego logowania
     - DEBUG - dla szczegółowego logowania
     - CRITICAL - dla pełnego logowania z datą i czasem
   - Dodaj sufiks _LOG do nazwy pliku, aby włączyć logowanie do pliku

2. Uruchom ten skrypt, aby przetestować funkcje loggera przy aktualnych ustawieniach
"""

import logging
import os
import sys
import time
import traceback
from datetime import datetime
from pathlib import Path

# Dodaj katalog główny projektu do ścieżki Pythona
current_dir = Path(__file__).parent
sys.path.append(str(current_dir))

try:
    # Importuj bibliotekę Logger
    from core.logger import Logger
except ImportError as e:
    print(f"Błąd importu biblioteki Logger: {e}")
    print("Upewnij się, że katalog core/ istnieje i zawiera plik logger.py")
    sys.exit(1)


# Klasa do zliczania logów według poziomów
class LogCounter:
    def __init__(self):
        self.info_count = 0
        self.debug_count = 0
        self.warning_count = 0
        self.error_count = 0
        self.critical_count = 0
        self.total_count = 0
        self.start_time = datetime.now()
        self.end_time = None

    def count(self, level):
        """Zwiększa licznik dla określonego poziomu logowania"""
        self.total_count += 1
        if level == logging.INFO:
            self.info_count += 1
        elif level == logging.DEBUG:
            self.debug_count += 1
        elif level == logging.WARNING:
            self.warning_count += 1
        elif level == logging.ERROR:
            self.error_count += 1
        elif level == logging.CRITICAL:
            self.critical_count += 1

    def finish(self):
        """Kończy pomiar czasu"""
        self.end_time = datetime.now()

    def get_duration(self):
        """Zwraca czas trwania testu w sekundach"""
        if self.end_time:
            return (self.end_time - self.start_time).total_seconds()
        return (datetime.now() - self.start_time).total_seconds()

    def print_statistics(self):
        """Wyświetla podsumowanie statystyk logowania"""
        print("\n=== Statystyka Logowania ===")
        print(f"Całkowita liczba logów: {self.total_count}")
        print(f"INFO: {self.info_count}")
        print(f"DEBUG: {self.debug_count}")
        print(f"WARNING: {self.warning_count}")
        print(f"ERROR: {self.error_count}")
        print(f"CRITICAL: {self.critical_count}")
        print(f"Czas wykonania testów: {self.get_duration():.2f} s")


# Globalny licznik logów
log_counter = LogCounter()


# Klasa MonitorHandler do przechwytywania i zliczania logów
class MonitorHandler(logging.Handler):
    def emit(self, record):
        log_counter.count(record.levelno)


def test_basic_logging():
    """Test podstawowych funkcji logowania"""
    log = Logger()
    print("\n=== Test podstawowych funkcji logowania ===")

    log.info("To jest wiadomość INFO")
    log.debug("To jest wiadomość DEBUG")
    log.warning("To jest wiadomość WARNING")
    log.error("To jest wiadomość ERROR")
    log.critical("To jest wiadomość CRITICAL")

    # Test logowania z dodatkowym stacklevel
    def nested_function():
        log.info("Wiadomość z funkcji zagnieżdżonej", stacklevel=2)

    nested_function()


def test_exception_logging():
    """Test logowania wyjątków"""
    log = Logger()
    print("\n=== Test logowania wyjątków ===")

    try:
        # Wywołaj błąd dzielenia przez zero
        result = 10 / 0
    except Exception as e:
        log.exception(f"Złapano wyjątek: {e}")
        log.error("Logowanie błędu bez traceback")
        log.error("Logowanie błędu z traceback", exc_info=True)


def test_append_mode():
    """Test trybu append w logowaniu"""
    log = Logger()
    print("\n=== Test trybu append ===")

    log.debug("Normalny log DEBUG")

    # Symulacja postępu
    for i in range(1, 11):
        log.debug(f"Postęp operacji: {i*10}%", append=True)
        time.sleep(0.2)  # Skrócony czas dla szybszego testu

    log.debug("\nPostęp zakończony")


def test_file_output():
    """Test czy logowanie do pliku działa przy obecnych ustawieniach"""
    log = Logger()
    print("\n=== Test logowania do pliku (przy obecnych ustawieniach) ===")

    log.info(
        "Testowa wiadomość INFO - sprawdź plik logów jeśli logowanie do pliku jest włączone"
    )
    log.debug(
        "Testowa wiadomość DEBUG - sprawdź plik logów jeśli logowanie do pliku jest włączone"
    )
    log.warning(
        "Testowa wiadomość WARNING - sprawdź plik logów jeśli logowanie do pliku jest włączone"
    )
    log.error(
        "Testowa wiadomość ERROR - sprawdź plik logów jeśli logowanie do pliku jest włączone"
    )
    log.critical(
        "Testowa wiadomość CRITICAL - sprawdź plik logów jeśli logowanie do pliku jest włączone"
    )

    if log.file_logging_enabled and log.file_handler:
        print(
            f"Logowanie do pliku jest włączone. Zapisy powinny znajdować się w: {log.log_file}"
        )
    else:
        print(
            "Logowanie do pliku jest wyłączone lub niedostępne przy obecnym poziomie logowania."
        )


def setup_monitoring():
    """Konfiguruje monitoring logów"""
    # Pobierz logger z biblioteki
    logger = logging.getLogger("logger")

    # Dodaj handler do monitorowania
    monitor_handler = MonitorHandler()
    logger.addHandler(monitor_handler)

    return monitor_handler


def main():
    """Funkcja główna"""
    log = Logger()

    # Konfiguracja monitorowania
    monitor_handler = setup_monitoring()

    print("=== Test biblioteki Logger_LIB ===")
    print(f"Wersja biblioteki: {Logger.VERSION}")
    print("Katalog bieżący:", current_dir)
    print(f"Aktualny tryb logowania: {log.logging_mode}")
    print(
        f"Logowanie do pliku: {'Włączone' if log.file_logging_enabled else 'Wyłączone'}"
    )

    try:
        # Uruchom testy
        test_basic_logging()
        test_exception_logging()
        test_append_mode()
        test_file_output()

        # Zakończ liczenie
        log_counter.finish()

        # Usuń handler monitorujący przed zamknięciem
        if monitor_handler:
            logging.getLogger("logger").removeHandler(monitor_handler)

        # Zamknij logger
        log.close()

        # Wyświetl statystyki
        log_counter.print_statistics()

        # Sprawdź dostępność pliku logów
        if log.file_logging_enabled and hasattr(log, "log_file") and log.log_file:
            log_path = Path(log.log_file)
            if log_path.exists():
                size = log_path.stat().st_size
                print(f"\nPlik logów: {log_path}")
                print(f"Rozmiar pliku: {size/1024:.2f} KB")

        print("\nTest zakończony. Logger zamknięty.")

    except Exception as e:
        print(f"Wystąpił nieoczekiwany błąd: {e}")
        traceback.print_exc()

        # Zakończ liczenie nawet w przypadku błędu
        log_counter.finish()
        log_counter.print_statistics()

        # Spróbuj zamknąć logger w przypadku błędu
        try:
            if monitor_handler:
                logging.getLogger("logger").removeHandler(monitor_handler)
            log.close()
        except:
            pass


if __name__ == "__main__":
    main()
