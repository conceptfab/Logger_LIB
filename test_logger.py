#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Testy dla biblioteki logger.
"""

import os
import re
import sys
import time
import unittest

from core.logger import Logger

# Dodawanie ścieżki projektu do sys.path
KATALOG_PROJEKTU = os.path.dirname(os.path.abspath(__file__))
if KATALOG_PROJEKTU not in sys.path:
    sys.path.append(KATALOG_PROJEKTU)


class TestLogger(unittest.TestCase):
    """Testy dla klasy Logger."""

    def setUp(self):
        """Inicjalizacja przed każdym testem."""
        self.logger = Logger()
        # Włączamy logowanie do pliku dla testów
        self.logger.set_file_logging(True)
        self.test_message = "Testowa wiadomość"
        self.test_data = {"klucz": "wartość", "liczba": 123}
        self.log_file = os.path.join(KATALOG_PROJEKTU, "logs", "log.log")

    def tearDown(self):
        """Czyszczenie po każdym teście."""
        # Wyłączamy logowanie do pliku
        self.logger.set_file_logging(False)

    def _read_log_file(self):
        """Odczytuje zawartość pliku logów."""
        if os.path.exists(self.log_file):
            with open(self.log_file, "r", encoding="utf-8") as f:
                return f.read()
        return ""

    def test_info_logging(self):
        """Test logowania wiadomości informacyjnych."""
        self.logger.info(self.test_message)
        time.sleep(0.1)  # Czekamy na zapis do pliku
        log_content = self._read_log_file()
        self.assertIn(self.test_message, log_content)
        self.assertIn("INFO", log_content)

    def test_warning_logging(self):
        """Test logowania ostrzeżeń."""
        self.logger.warning(self.test_message)
        time.sleep(0.1)  # Czekamy na zapis do pliku
        log_content = self._read_log_file()
        self.assertIn(self.test_message, log_content)
        self.assertIn("WARNING", log_content)

    def test_error_logging(self):
        """Test logowania błędów."""
        self.logger.error(self.test_message)
        time.sleep(0.1)  # Czekamy na zapis do pliku
        log_content = self._read_log_file()
        self.assertIn(self.test_message, log_content)
        self.assertIn("ERROR", log_content)

    def test_data_logging(self):
        """Test logowania danych."""
        self.logger.info(f"Dane testowe: {self.test_data}")
        time.sleep(0.1)  # Czekamy na zapis do pliku
        log_content = self._read_log_file()
        self.assertIn(str(self.test_data), log_content)
        self.assertIn("INFO", log_content)

    def test_multiple_loggers(self):
        """Test działania wielu instancji loggera (Singleton)."""
        logger2 = Logger()
        self.assertEqual(self.logger, logger2)  # Powinny być tą samą instancją

    def test_log_format(self):
        """Test formatowania wiadomości logów."""
        self.logger.info(self.test_message)
        time.sleep(0.1)  # Czekamy na zapis do pliku
        log_content = self._read_log_file()

        # Sprawdzenie formatu wiadomości
        self.assertIn("INFO", log_content)
        self.assertIn(self.test_message, log_content)

        # Sprawdzenie formatu daty (HH:MM:SS)
        time_pattern = r"\d{2}:\d{2}:\d{2}"
        self.assertTrue(
            re.search(time_pattern, log_content),
            "Wiadomość powinna zawierać znacznik czasu w formacie HH:MM:SS",
        )

        # Sprawdzenie pełnego formatu logu
        log_pattern = r"\d{2}:\d{2}:\d{2} \| INFO\s+\| .*:\d+ \| " + re.escape(
            self.test_message
        )
        self.assertTrue(
            re.search(log_pattern, log_content),
            "Wiadomość powinna być w formacie: CZAS | POZIOM | PLIK:NR_LINII | WIADOMOŚĆ",
        )

    def test_file_logging_toggle(self):
        """Test włączania i wyłączania logowania do pliku."""
        # Upewnij się, że logowanie do pliku jest włączone dla tego testu
        self.logger.set_file_logging(True)

        # Zapisz wiadomość testową
        test_msg = "Test logowania do pliku: włączone"
        self.logger.info(test_msg)
        time.sleep(0.1)  # Czekamy na zapis do pliku

        # Sprawdź czy wiadomość została zapisana
        log_content = self._read_log_file()
        self.assertIn(test_msg, log_content)

        # Wyłącz logowanie do pliku
        self.logger.set_file_logging(False)

        # Sprawdź, czy handler pliku został zamknięty
        self.assertIsNone(self.logger.file_handler)

        # Zapisz nową wiadomość
        test_msg2 = "Test logowania do pliku: wyłączone"
        self.logger.info(test_msg2)
        time.sleep(0.1)

        # Sprawdź, czy wiadomość NIE została zapisana do pliku
        log_content = self._read_log_file()
        self.assertIn(test_msg, log_content)  # Stara wiadomość powinna być
        self.assertNotIn(
            test_msg2, log_content
        )  # Nowa wiadomość nie powinna być zapisana


if __name__ == "__main__":
    unittest.main()
