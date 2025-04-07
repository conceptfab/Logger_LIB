"""
Biblioteka Logger_LIB - zaawansowany system logowania dla aplikacji Python.

Wersja: 0.2

Biblioteka implementuje wzorzec Singleton do centralnego zarządzania logowaniem.
Oferuje następujące funkcjonalności:
- Elastyczne poziomy logowania (NONE, INFO, DEBUG, CRITICAL)
- Logowanie do konsoli z różnymi formatami w zależności od poziomu
- Logowanie do pliku z automatyczną rotacją dzienną
- Obsługa różnych formatów wiadomości
- Bezpieczne zarządzanie zasobami
- Informacje o pliku i numerze linii w logach
"""

# logger.py
import datetime
import io
import logging
import logging.handlers
import os
import sys
import traceback
from typing import Any, ClassVar, Dict, List, Optional, Type, Union

# Import C4D tylko jeśli jest dostępne - dla elastyczności
_C4D_AVAILABLE = False


class Logger:
    """
    Klasa implementująca wzorzec Singleton do centralnego zarządzania logowaniem.

    Funkcjonalności:
    - Używa standardowego `logging.StreamHandler` do logowania na konsolę
      (sys.stdout).
    - Obsługuje następujące tryby logowania z różnymi formatami na konsoli:
        * 0 (LOG_MODE_NONE): nic nie jest wyświetlane
        * "INFO" (LOG_MODE_INFO): Wyświetla tylko INFO i wyższe
          (WARNING, ERROR, CRITICAL). Format konsoli: ▶ wiadomość
        * "DEBUG" (LOG_MODE_DEBUG): Wyświetla DEBUG i wyższe.
          Format konsoli: ▶ POZIOM : plik:linia ▶ wiadomość
        * "CRITICAL" (LOG_MODE_CRITICAL): Wyświetla DEBUG i wyższe.
          Format konsoli: CZAS ▶ POZIOM : plik:linia ▶ wiadomość
    - Na starcie sprawdza, czy w folderze logger.py istnieje plik o nazwie
      '0', 'INFO', 'DEBUG' lub 'CRITICAL' i rozmiarze 0. Jeśli tak, używa
      nazwy pliku jako początkowego trybu logowania. W przeciwnym razie używa
      wartości DEFAULT_LOG_MODE.
    - Komunikaty informacyjne o procesie ustalania trybu logowania są logowane
      jako DEBUG.
    - Logowanie do pliku jest aktywne tylko dla poziomów DEBUG i CRITICAL.
    - W trybie plikowym:
        - Tworzy katalog 'logs' (poziom wyżej niż ten skrypt).
        - Zapisuje do pliku `logs/log.log` z automatyczną rotacją dzienną.
        - Przechowuje 7 ostatnich zrotowanych plików logów.
        - Format pliku jest zawsze szczegółowy.
    - W logach (konsola w trybach DEBUG/CRITICAL i plik) zawiera informację
      o pliku i numerze linii *faktycznego miejsca wywołania* funkcji
      logującej (np. `log.info()` w `txm.pyp`), dzięki użyciu `stacklevel=2`.
    - Implementuje wzorzec Singleton.
    - Komunikaty o przebiegu inicjalizacji (tworzenie handlera, konfiguracja pliku,
      etc.) są logowane na poziomie DEBUG, więc pojawiają się tylko w trybach
      DEBUG i CRITICAL.
    - Zawiera metodę close() do poprawnego zamykania handlerów przy zakończeniu pracy.
    """

    # Stałe konfiguracyjne jako ClassVar
    _instance: ClassVar[Optional["Logger"]] = None
    _initialized: ClassVar[bool] = False
    VERSION: ClassVar[str] = "0.2"

    # Stałe konfiguracyjne
    LOG_MODE_NONE: ClassVar[int] = 0
    LOG_MODE_INFO: ClassVar[str] = "INFO"
    LOG_MODE_DEBUG: ClassVar[str] = "DEBUG"
    LOG_MODE_CRITICAL: ClassVar[str] = "CRITICAL"

    FILE_LOGGING_MODES: ClassVar[List[str]] = [LOG_MODE_DEBUG, LOG_MODE_CRITICAL]

    DEFAULT_LOG_MODE: ClassVar[Union[int, str]] = (
        LOG_MODE_CRITICAL  # Domyślny tryb, jeśli plik kontrolny nie zostanie znaleziony
    )
    LOG_DIRECTORY: ClassVar[str] = "logs"
    LOG_FILENAME_PREFIX: ClassVar[str] = "log"

    # --- Formaty Logowania ---
    # Zmodyfikowane formaty konsoli z różnymi znakami ASCII
    # dla różnych poziomów
    CONSOLE_FORMAT_INFO: ClassVar[str] = (
        "ℹ %(levelname)-7s: %(filename)s:%(lineno)d → %(message)s"
    )
    CONSOLE_FORMAT_DEBUG: ClassVar[str] = (
        "⚙ %(levelname)-7s: %(filename)s:%(lineno)d → %(message)s"
    )
    CONSOLE_FORMAT_WARNING: ClassVar[str] = (
        "⚠ %(levelname)-7s: %(filename)s:%(lineno)d → %(message)s"
    )
    CONSOLE_FORMAT_ERROR: ClassVar[str] = (
        "✖✖ %(levelname)-7s: %(filename)s:%(lineno)d → %(message)s"
    )
    CONSOLE_FORMAT_CRITICAL: ClassVar[str] = (
        "%(asctime)s ⚠⚠⚠ %(levelname)-7s: %(filename)s:%(lineno)d → %(message)s"
    )
    FILE_FORMAT: ClassVar[str] = (
        "%(asctime)s | %(levelname)-7s | %(filename)s:%(lineno)d | %(message)s"
    )

    LOG_DATE_FORMAT: ClassVar[str] = "%H:%M:%S"
    STACKLEVEL: ClassVar[int] = 2

    def __new__(cls: Type["Logger"]) -> "Logger":
        if cls._instance is None:
            cls._instance = super(Logger, cls).__new__(cls)
        return cls._instance

    def __init__(self) -> None:
        if Logger._initialized:
            return

        # Lista na komunikaty inicjalizacyjne
        init_messages: List[str] = []
        is_init_successful = True  # Flaga powodzenia inicjalizacji

        try:
            self.logger = logging.getLogger("logger")
            self.log_file: Optional[str] = None
            self.console_handler: Optional[logging.Handler] = None
            self.file_handler: Optional[logging.Handler] = None

            # Dodaj informację o wersji do komunikatów inicjalizacyjnych
            init_messages.append(f"Inicjalizacja Logger_LIB wersja {Logger.VERSION}")

            script_dir = os.path.dirname(os.path.abspath(__file__))
            self.log_dir = os.path.join(
                os.path.dirname(script_dir), Logger.LOG_DIRECTORY
            )

            # --- Logika ustalania początkowego trybu logowania ---
            initial_mode = Logger.DEFAULT_LOG_MODE
            mode_source = f"domyślna wartość w kodzie ({Logger.DEFAULT_LOG_MODE})"

            level_files_map = {
                "0": Logger.LOG_MODE_NONE,
                "INFO": Logger.LOG_MODE_INFO,
                "DEBUG": Logger.LOG_MODE_DEBUG,
                "CRITICAL": Logger.LOG_MODE_CRITICAL,
            }

            for filename, mode in level_files_map.items():
                filepath = os.path.join(script_dir, filename)
                try:
                    if os.path.isfile(filepath) and os.path.getsize(filepath) == 0:
                        initial_mode = mode
                        mode_source = f"plik kontrolny '{filename}' (rozmiar 0)"
                        init_messages.append(
                            f"Znaleziono plik kontrolny '{filename}'. Ustawiono tryb na: {mode}"
                        )
                        break
                except OSError as e:
                    init_messages.append(
                        f"Ostrzeżenie: Nie można sprawdzić pliku '{filepath}': {e}. Kontynuacja z trybem: {initial_mode}"
                    )
                except Exception as e:
                    init_messages.append(
                        f"Ostrzeżenie: Niespodziewany błąd podczas sprawdzania pliku '{filepath}': {e}. Kontynuacja z trybem: {initial_mode}"
                    )

            init_messages.append(
                f"Początkowy tryb logowania ({initial_mode}) ustalony na podstawie: {mode_source}."
            )

            self._configure_basic_logger()
            self.logging_mode = Logger.LOG_MODE_NONE  # Tymczasowo

            # --- Konfiguracja handlerów i ustawienie trybu ---
            critical_error = False
            if initial_mode != Logger.LOG_MODE_NONE:
                if not self._configure_console_handler():
                    critical_error = True
                    is_init_successful = False
                    init_messages.append(
                        "KRYTYCZNY BŁĄD: Nie można zainicjalizować handlera konsoli."
                    )
                else:
                    # Skonfiguruj plik, jeśli tryb tego wymaga
                    if initial_mode in Logger.FILE_LOGGING_MODES:
                        if not self._configure_file_handler():
                            init_messages.append(
                                "Ostrzeżenie: Nie udało się skonfigurować logowania do pliku. Kontynuacja tylko z logowaniem do konsoli."
                            )
                            # Brak file_handler nie jest krytycznym błędem

                    # Ustaw właściwy tryb
                    if not self.set_logging_mode(initial_mode):
                        init_messages.append(
                            f"Ostrzeżenie: Nie udało się ustawić trybu logowania na {initial_mode}."
                        )
            else:
                # Jeśli tryb początkowy to NONE, zapisujemy stan
                self.logging_mode = Logger.LOG_MODE_NONE
                init_messages.append(
                    "Tryb logowania ustawiony na NONE (0). Logowanie wyłączone."
                )

        except Exception as e:
            is_init_successful = False
            critical_error = True
            init_messages.append(
                f"KRYTYCZNY BŁĄD podczas inicjalizacji Loggera: {str(e)}"
            )
            # Użyj print jako ostatniej deski ratunku
            print(f"KRYTYCZNY BŁĄD podczas inicjalizacji Loggera: {str(e)}")
            print(traceback.format_exc())
        finally:
            # --- Zakończenie inicjalizacji ---
            Logger._initialized = is_init_successful

            # Logowanie zebranych komunikatów inicjalizacyjnych
            if critical_error:
                # Użyj print jako ostateczności
                print("KRYTYCZNY BŁĄD Loggera: Logger nie będzie działał poprawnie.")
                print("Zebrane komunikaty inicjalizacyjne:")
                for msg in init_messages:
                    print(f"  [INIT] {msg}")
            elif (
                self.logging_mode in [Logger.LOG_MODE_DEBUG, Logger.LOG_MODE_CRITICAL]
                and self.logger.hasHandlers()
            ):
                # Loguj tylko w trybach DEBUG/CRITICAL
                stack_level_for_init_logs = Logger.STACKLEVEL + 1
                self.logger.debug(
                    "--- Rozpoczęcie logów inicjalizacji Loggera ---",
                    stacklevel=stack_level_for_init_logs,
                )
                for msg in init_messages:
                    self.logger.debug(msg, stacklevel=stack_level_for_init_logs)
                self.logger.debug(
                    f"Inicjalizacja Loggera zakończona. Finalny tryb: {self.logging_mode}.",
                    stacklevel=stack_level_for_init_logs,
                )
                self.logger.debug(
                    "--- Koniec logów inicjalizacji Loggera ---",
                    stacklevel=stack_level_for_init_logs,
                )

    def _configure_basic_logger(self) -> None:
        """Konfiguruje podstawowe ustawienia loggera."""
        self.logger.setLevel(logging.DEBUG)
        self.logger.propagate = False

        for handler in self.logger.handlers[:]:
            self.logger.removeHandler(handler)
            handler.close()

    def _set_logging_level_for_mode(self, mode: Union[int, str]) -> None:
        """Ustawia odpowiedni poziom logowania dla HANDLERA KONSOLI."""
        if not self.console_handler:
            return

        level = logging.INFO
        if mode == Logger.LOG_MODE_NONE:
            level = logging.CRITICAL + 1
        elif mode == Logger.LOG_MODE_INFO:
            level = logging.INFO
        elif mode == Logger.LOG_MODE_DEBUG:
            level = logging.DEBUG
        elif mode == Logger.LOG_MODE_CRITICAL:
            level = logging.DEBUG
        else:
            # Log warning jeśli logger jest już gotowy
            if Logger._initialized and self.logger.hasHandlers():
                self.warning(
                    f"Nieznany tryb logowania '{mode}'. Ustawiono poziom INFO dla konsoli.",
                    stacklevel=Logger.STACKLEVEL + 2,
                )  # Wskazuje na miejsce wywołania _set...
            else:
                print(
                    f"Ostrzeżenie Loggera: Nieznany tryb logowania '{mode}'. Ustawiono poziom INFO dla konsoli."
                )
            level = logging.INFO

        self.console_handler.setLevel(level)

    def _configure_console_handler(self) -> bool:
        """Konfiguruje handler konsoli. Zwraca True w przypadku sukcesu."""
        try:
            self.console_handler = logging.StreamHandler(sys.stdout)
            self.console_handler.setLevel(logging.DEBUG)  # Poziom zostanie dostosowany

            # Używamy niestandardowego formatera, który dobierze format na podstawie poziomu
            self.console_handler.setFormatter(
                LevelSpecificFormatter(
                    info_fmt=Logger.CONSOLE_FORMAT_INFO,
                    debug_fmt=Logger.CONSOLE_FORMAT_DEBUG,
                    warning_fmt=Logger.CONSOLE_FORMAT_WARNING,
                    error_fmt=Logger.CONSOLE_FORMAT_ERROR,
                    critical_fmt=Logger.CONSOLE_FORMAT_CRITICAL,
                    datefmt=Logger.LOG_DATE_FORMAT,
                )
            )

            self.logger.addHandler(self.console_handler)
            return True
        except Exception as e:
            # Krytyczny błąd - ten print pozostaje, bo logger może nie działać
            print(
                f"KRYTYCZNY BŁĄD Loggera: Nie można skonfigurować logowania do konsoli: {e}"
            )
            if self.console_handler and self.console_handler in self.logger.handlers:
                self.logger.removeHandler(self.console_handler)
            self.console_handler = None
            return False

    def _configure_file_handler(self) -> bool:
        """Konfiguruje handler pliku z rotacją. Zwraca True w przypadku sukcesu."""
        if not self._ensure_log_directory():
            return False

        try:
            log_filename = f"{Logger.LOG_FILENAME_PREFIX}.log"
            self.log_file = os.path.join(self.log_dir, log_filename)

            formatter = logging.Formatter(
                fmt=Logger.FILE_FORMAT, datefmt=Logger.LOG_DATE_FORMAT
            )

            # Użycie TimedRotatingFileHandler zamiast zwykłego FileHandler
            self.file_handler = logging.handlers.TimedRotatingFileHandler(
                self.log_file,
                when="midnight",  # Rotacja o północy
                interval=1,  # Co jeden dzień
                backupCount=7,  # Zachowaj 7 ostatnich plików
                encoding="utf-8",
            )

            # Format nazwy po rotacji: log.log.YYYY-MM-DD
            self.file_handler.suffix = "%Y-%m-%d"

            self.file_handler.setLevel(logging.DEBUG)
            self.file_handler.setFormatter(formatter)
            self.logger.addHandler(self.file_handler)

            self.logger.debug(
                f"Handler pliku z rotacją skonfigurowany: {self.log_file}",
                stacklevel=Logger.STACKLEVEL + 1,
            )
            return True
        except Exception as e:
            self.critical(
                f"Nie można skonfigurować logowania do pliku ({self.log_file if hasattr(self, 'log_file') else 'brak ścieżki'}). Błąd: {e}",
                exc_info=True,
                stacklevel=Logger.STACKLEVEL + 2,
            )
            if self.file_handler and self.file_handler in self.logger.handlers:
                self.logger.removeHandler(self.file_handler)
            self.file_handler = None
            return False

    def _ensure_log_directory(self) -> bool:
        """Upewnia się, że katalog logów istnieje."""
        if not os.path.exists(self.log_dir):
            try:
                os.makedirs(self.log_dir)
                # Log DEBUG jest OK, bo wywoływane gdy logger ma już przynajmniej handler konsoli
                self.logger.debug(
                    f"Utworzono katalog logów: {self.log_dir}",
                    stacklevel=Logger.STACKLEVEL + 1,
                )
                return True
            except OSError as e:
                # Użyj logger.critical, bo logger powinien już działać
                self.critical(
                    f"Nie można utworzyć katalogu logów: {self.log_dir}. Błąd: {e}",
                    stacklevel=Logger.STACKLEVEL + 2,
                )
                return False
        return True

    def set_logging_mode(self, mode: Union[int, str]) -> bool:
        """
        Zmienia tryb logowania w czasie działania, aktualizując poziom
        oraz FORMAT handlera konsoli.
        """
        valid_modes = [
            Logger.LOG_MODE_NONE,
            Logger.LOG_MODE_INFO,
            Logger.LOG_MODE_DEBUG,
            Logger.LOG_MODE_CRITICAL,
            "ERROR",  # Dodajemy obsługę poziomu ERROR
        ]
        if mode not in valid_modes:
            self.error(
                f"Nieprawidłowy tryb logowania: {mode}. Dozwolone: 0, INFO, DEBUG, CRITICAL, ERROR.",
                stacklevel=Logger.STACKLEVEL + 1,
            )
            return False

        # Sprawdzamy _initialized tylko dla zmiany trybu *po* inicjalizacji
        is_initial_set = not Logger._initialized
        if mode == self.logging_mode and not is_initial_set:
            return True

        old_mode = self.logging_mode
        self.logging_mode = mode

        # Loguj zmianę trybu jako DEBUG, ale tylko jeśli nie jest to pierwsze ustawienie
        if not is_initial_set:
            self.logger.debug(
                f"Zmieniono tryb logowania z '{old_mode}' na '{mode}'",
                stacklevel=Logger.STACKLEVEL + 1,
            )
        # else: Log o początkowym trybie jest na końcu __init__

        # --- Konfiguracja Handlera Konsoli ---
        if mode == Logger.LOG_MODE_NONE:
            if self.console_handler:
                self.logger.removeHandler(self.console_handler)
                self.console_handler.close()
                self.console_handler = None
        else:
            if not self.console_handler:
                if not self._configure_console_handler():
                    self.logging_mode = old_mode  # Przywróć stary tryb
                    self.error(
                        "Nie udało się odtworzyć handlera konsoli przy zmianie trybu.",
                        stacklevel=Logger.STACKLEVEL + 1,
                    )
                    return False

            self._set_logging_level_for_mode(mode)

        # --- Konfiguracja Handlera Pliku ---
        # Ta logika jest wywoływana zarówno przy pierwszym ustawieniu, jak i przy zmianie trybu
        if mode in Logger.FILE_LOGGING_MODES:
            if not self.file_handler:
                # Próba konfiguracji handlera pliku
                if not self._configure_file_handler():
                    self.warning(
                        "Nie udało się skonfigurować logowania do pliku.",
                        stacklevel=Logger.STACKLEVEL + 1,
                    )
                    # Kontynuuj, konsola może działać
        else:  # Tryb nie wymaga logowania do pliku
            if self.file_handler:
                # Wyłączanie logowania do pliku jest logowane jako DEBUG
                if (
                    not is_initial_set
                ):  # Loguj tylko przy zmianie trybu, nie przy starcie w trybie bez pliku
                    self.logger.debug(
                        "Wyłączanie logowania do pliku z powodu zmiany trybu.",
                        stacklevel=Logger.STACKLEVEL + 1,
                    )
                self.logger.removeHandler(self.file_handler)
                self.file_handler.close()
                self.file_handler = None
                self.log_file = None

        return True

    def close(self) -> None:
        """
        Poprawnie zamyka wszystkie handlery i zwalnia zasoby.
        Powinno być wywołane przy zakończeniu programu.
        """
        if not Logger._initialized:
            return

        self.logger.debug(
            "Zamykanie Loggera i zwalnianie zasobów...", stacklevel=Logger.STACKLEVEL
        )

        # Zamknij handler konsoli
        if self.console_handler:
            self.logger.removeHandler(self.console_handler)
            self.console_handler.close()
            self.console_handler = None

        # Zamknij handler pliku
        if self.file_handler:
            self.logger.removeHandler(self.file_handler)
            self.file_handler.close()
            self.file_handler = None

        # Nie resetujemy _initialized, aby zapobiec ponownemu tworzeniu loggera
        # gdy użytkownik przypadkowo wywoła Logger() po close()
        self.logging_mode = Logger.LOG_MODE_NONE
        self.log_file = None

    # --- Metody publiczne do logowania ---

    def debug(self, message: str, *args: Any, **kwargs: Any) -> None:
        """
        Loguje wiadomość na poziomie DEBUG.

        Args:
            message: Wiadomość do zalogowania
            *args: Dodatkowe argumenty dla logger.debug
            append: Jeśli True, dodaje wiadomość do poprzedniej linii bez nowej linii
            **kwargs: Dodatkowe argumenty słownikowe dla logger.debug
        """
        kwargs["stacklevel"] = kwargs.get("stacklevel", Logger.STACKLEVEL + 1)
        append = kwargs.pop("append", False)

        if self.logger.isEnabledFor(logging.DEBUG):
            if append:
                # Używamy własnego handlera do obsługi append zamiast print
                if self.console_handler and isinstance(
                    self.console_handler.stream, io.TextIOWrapper
                ):
                    # Wydrukuj tylko samą wiadomość bez formatowania
                    self.console_handler.stream.write(f"\r{message}")
                    self.console_handler.stream.flush()
                else:
                    # Fallback na print jeśli brak console_handler
                    print(f"\r{message}", end="", flush=True)
            else:
                self.logger.debug(message, *args, **kwargs)

    def info(self, message: str, *args: Any, **kwargs: Any) -> None:
        """
        Loguje wiadomość na poziomie INFO.

        Args:
            message: Wiadomość do zalogowania
            *args: Dodatkowe argumenty dla logger.info
            **kwargs: Dodatkowe argumenty słownikowe dla logger.info
        """
        kwargs["stacklevel"] = kwargs.get("stacklevel", Logger.STACKLEVEL + 1)
        if self.logger.isEnabledFor(logging.INFO):
            self.logger.info(message, *args, **kwargs)

    def warning(self, message: str, *args: Any, **kwargs: Any) -> None:
        """
        Loguje wiadomość na poziomie WARNING.

        Args:
            message: Wiadomość do zalogowania
            *args: Dodatkowe argumenty dla logger.warning
            **kwargs: Dodatkowe argumenty słownikowe dla logger.warning
        """
        kwargs["stacklevel"] = kwargs.get("stacklevel", Logger.STACKLEVEL + 1)
        if self.logger.isEnabledFor(logging.WARNING):
            self.logger.warning(message, *args, **kwargs)

    def error(
        self, message: str, *args: Any, exc_info: bool = False, **kwargs: Any
    ) -> None:
        """
        Loguje wiadomość na poziomie ERROR.

        Args:
            message: Wiadomość do zalogowania
            *args: Dodatkowe argumenty dla logger.error
            exc_info: Jeśli True, dołącza informacje o wyjątku
            **kwargs: Dodatkowe argumenty słownikowe dla logger.error
        """
        kwargs["stacklevel"] = kwargs.get("stacklevel", Logger.STACKLEVEL + 1)
        if self.logger.isEnabledFor(logging.ERROR):
            self.logger.error(message, *args, exc_info=exc_info, **kwargs)

    def critical(
        self, message: str, *args: Any, exc_info: bool = False, **kwargs: Any
    ) -> None:
        """
        Loguje wiadomość na poziomie CRITICAL.

        Args:
            message: Wiadomość do zalogowania
            *args: Dodatkowe argumenty dla logger.critical
            exc_info: Jeśli True, dołącza informacje o wyjątku
            **kwargs: Dodatkowe argumenty słownikowe dla logger.critical
        """
        kwargs["stacklevel"] = kwargs.get("stacklevel", Logger.STACKLEVEL + 1)
        if self.logger.isEnabledFor(logging.CRITICAL):
            self.logger.critical(message, *args, exc_info=exc_info, **kwargs)

    def exception(self, message: str, *args: Any, **kwargs: Any) -> None:
        """
        Loguje wiadomość na poziomie ERROR wraz z informacją o wyjątku.

        Args:
            message: Wiadomość do zalogowania
            *args: Dodatkowe argumenty dla logger.error
            **kwargs: Dodatkowe argumenty słownikowe dla logger.error
        """
        kwargs["stacklevel"] = kwargs.get("stacklevel", Logger.STACKLEVEL + 1)
        # Wywołanie error z exc_info=True
        self.error(message, *args, exc_info=True, **kwargs)


# Niestandardowy formatter, który używa różnych formatów dla różnych poziomów logowania
class LevelSpecificFormatter(logging.Formatter):
    def __init__(
        self,
        info_fmt=None,
        debug_fmt=None,
        warning_fmt=None,
        error_fmt=None,
        critical_fmt=None,
        datefmt=None,
    ):
        super().__init__(datefmt=datefmt)
        self.formatters = {
            logging.INFO: logging.Formatter(fmt=info_fmt, datefmt=datefmt),
            logging.DEBUG: logging.Formatter(fmt=debug_fmt, datefmt=datefmt),
            logging.WARNING: logging.Formatter(fmt=warning_fmt, datefmt=datefmt),
            logging.ERROR: logging.Formatter(fmt=error_fmt, datefmt=datefmt),
            logging.CRITICAL: logging.Formatter(fmt=critical_fmt, datefmt=datefmt),
        }

    def format(self, record):
        formatter = self.formatters.get(record.levelno, self.formatters[logging.INFO])
        return formatter.format(record)


# Eksport klasy Logger
__all__ = ["Logger"]
