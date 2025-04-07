"""
Biblioteka Logger_LIB - zaawansowany system logowania dla aplikacji Python.

Wersja: 0.2x

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
    VERSION: ClassVar[str] = "0.25"

    # Stałe konfiguracyjne
    LOG_MODE_NONE: ClassVar[int] = 0
    LOG_MODE_INFO: ClassVar[str] = "INFO"
    LOG_MODE_DEBUG: ClassVar[str] = "DEBUG"
    LOG_MODE_CRITICAL: ClassVar[str] = "CRITICAL"

    LOG_FILE_SUFFIX: ClassVar[str] = "_LOG"  # Sufiks aktywujący logowanie do pliku
    FILE_LOGGING_ENABLED: ClassVar[bool] = (
        False  # Domyślnie logowanie do pliku wyłączone
    )

    DEFAULT_LOG_MODE: ClassVar[Union[int, str]] = LOG_MODE_NONE  # Domyślny tryb (NONE)
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
        "⚠⚠⚠ CRITICAL [%(asctime)s]: %(filename)s:%(lineno)d → %(message)s"
    )
    # Nowe formaty dla trybu CRITICAL
    CONSOLE_FORMAT_WARNING_CRITICAL: ClassVar[str] = (
        "⚠ [%(asctime)s] %(levelname)-7s: %(filename)s:%(lineno)d → %(message)s"
    )
    CONSOLE_FORMAT_ERROR_CRITICAL: ClassVar[str] = (
        "✖✖ [%(asctime)s] %(levelname)-7s: %(filename)s:%(lineno)d → %(message)s"
    )
    CONSOLE_FORMAT_CRITICAL_CRITICAL: ClassVar[str] = (
        "⚠⚠⚠ [%(asctime)s] CRITICAL: %(filename)s:%(lineno)d → %(message)s"
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

        # Lista na komunikaty inicjalizacyjne z dodatkowym poziomem szczegółowości
        init_messages: List[str] = []
        is_init_successful = True

        try:
            script_dir = os.path.dirname(os.path.abspath(__file__))

            # Sprawdzenie plików kontrolnych
            level_files = {
                "INFO": Logger.LOG_MODE_INFO,
                "DEBUG": Logger.LOG_MODE_DEBUG,
                "CRITICAL": Logger.LOG_MODE_CRITICAL,
            }

            initial_mode = Logger.DEFAULT_LOG_MODE
            file_logging_enabled = False

            for filename, mode in level_files.items():
                # Sprawdzaj zarówno plik bez sufiksu, jak i z sufiksem _LOG
                for suffix in ["", Logger.LOG_FILE_SUFFIX]:
                    filepath = os.path.join(script_dir, filename + suffix)
                    try:
                        if os.path.isfile(filepath) and os.path.getsize(filepath) == 0:
                            initial_mode = mode
                            file_logging_enabled = suffix == Logger.LOG_FILE_SUFFIX
                            break
                    except Exception:
                        pass

            # Zwięzły komunikat inicjalizacyjny
            init_messages.append(
                f"Logger v{Logger.VERSION} skonfigurowany: tryb={initial_mode}, plik={'TAK' if file_logging_enabled else 'NIE'}"
            )

            self.logger = logging.getLogger("logger")
            self.log_file: Optional[str] = None
            self.console_handler: Optional[logging.Handler] = None
            self.file_handler: Optional[logging.Handler] = None

            self.log_dir = os.path.join(
                os.path.dirname(script_dir), Logger.LOG_DIRECTORY
            )

            # Ustawienie zmiennej klasowej i instancji
            Logger.FILE_LOGGING_ENABLED = file_logging_enabled
            self.file_logging_enabled = file_logging_enabled

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
                    if initial_mode in [
                        Logger.LOG_MODE_DEBUG,
                        Logger.LOG_MODE_CRITICAL,
                    ]:
                        if not self._configure_file_handler():
                            init_messages.append(
                                "Ostrzeżenie: Nie udało się skonfigurować logowania do pliku. Kontynuacja tylko z logowaniem do konsoli."
                            )

                    # Ustaw właściwy tryb
                    if not self.set_logging_mode(initial_mode):
                        init_messages.append(
                            f"Ostrzeżenie: Nie udało się ustawić trybu logowania na {initial_mode}."
                        )
            else:
                # Jeśli tryb początkowy to NONE, zapisujemy stan
                self.logging_mode = Logger.LOG_MODE_NONE

        except Exception as e:
            is_init_successful = False
            critical_error = True
            init_messages.append(
                f"KRYTYCZNY BŁĄD podczas inicjalizacji Loggera: {str(e)}"
            )
            print(f"KRYTYCZNY BŁĄD podczas inicjalizacji Loggera: {str(e)}")
            print(traceback.format_exc())
        finally:
            # --- Zakończenie inicjalizacji ---
            Logger._initialized = is_init_successful

            # Logowanie zebranych komunikatów inicjalizacyjnych
            if critical_error:
                print("KRYTYCZNY BŁĄD Loggera: Logger nie będzie działał poprawnie.")
                print("Zebrane komunikaty inicjalizacyjne:")
                for msg in init_messages:
                    print(f"  [INIT] {msg}")
            elif not critical_error and self.logger.hasHandlers():
                stack_level_for_init_logs = Logger.STACKLEVEL + 1
                self.logger.debug(
                    f"Logger v{Logger.VERSION} zainicjalizowany: tryb={self.logging_mode}, plik={'TAK' if self.file_logging_enabled else 'NIE'}",
                    stacklevel=stack_level_for_init_logs,
                )

                # Tylko w przypadku ostrzeżeń i błędów, wyświetlamy dodatkowe komunikaty
                for msg in init_messages:
                    if "Ostrzeżenie:" in msg or "BŁĄD" in msg:
                        self.logger.debug(msg, stacklevel=stack_level_for_init_logs)

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

        # Usunięcie wszystkich istniejących filtrów
        for filter in self.console_handler.filters[:]:
            self.console_handler.removeFilter(filter)

        if mode == Logger.LOG_MODE_NONE:
            # Wyłączamy wszystkie logi
            self.console_handler.setLevel(logging.CRITICAL + 1)
        elif mode == Logger.LOG_MODE_INFO:
            # Ustawiamy poziom na INFO, ale dodajemy filtr, który przepuszcza TYLKO INFO
            self.console_handler.setLevel(logging.INFO)
            self.console_handler.addFilter(
                lambda record: record.levelno == logging.INFO
            )
        elif mode == Logger.LOG_MODE_DEBUG:
            # Pokazujemy wszystkie logi od DEBUG wzwyż
            self.console_handler.setLevel(logging.DEBUG)
        elif mode == Logger.LOG_MODE_CRITICAL:
            # W trybie CRITICAL pokazujemy tylko WARNING i wyższe poziomy
            self.console_handler.setLevel(logging.WARNING)
            # Dodajemy filtr, który przepuszcza tylko WARNING i wyższe poziomy
            self.console_handler.addFilter(
                lambda record: record.levelno >= logging.WARNING
            )
        else:
            # Nieznany tryb - ustawiamy na INFO jako domyślny
            if Logger._initialized and self.logger.hasHandlers():
                self.warning(
                    f"Nieznany tryb logowania '{mode}'. Ustawiono poziom INFO dla konsoli.",
                    stacklevel=Logger.STACKLEVEL + 2,
                )
            else:
                print(
                    f"Ostrzeżenie Loggera: Nieznany tryb logowania '{mode}'. Ustawiono poziom INFO dla konsoli."
                )
            self.console_handler.setLevel(logging.INFO)
            self.console_handler.addFilter(
                lambda record: record.levelno == logging.INFO
            )

    def _configure_console_handler(self) -> bool:
        """Konfiguruje handler konsoli. Zwraca True w przypadku sukcesu."""
        try:
            self.console_handler = logging.StreamHandler(sys.stdout)
            self.console_handler.setLevel(logging.DEBUG)  # Poziom zostanie dostosowany

            # Dodanie formaterów dla trybu CRITICAL z datą/czasem
            self.critical_formatters = {
                logging.WARNING: logging.Formatter(
                    fmt=Logger.CONSOLE_FORMAT_WARNING_CRITICAL,
                    datefmt=Logger.LOG_DATE_FORMAT,
                ),
                logging.ERROR: logging.Formatter(
                    fmt=Logger.CONSOLE_FORMAT_ERROR_CRITICAL,
                    datefmt=Logger.LOG_DATE_FORMAT,
                ),
                logging.CRITICAL: logging.Formatter(
                    fmt=Logger.CONSOLE_FORMAT_CRITICAL_CRITICAL,
                    datefmt=Logger.LOG_DATE_FORMAT,
                ),
            }

            # Standardowy formatter dla innych trybów
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
            print(f"Błąd podczas konfiguracji handlera konsoli: {str(e)}")
            return False

    def _configure_file_handler(self) -> bool:
        """Konfiguruje handler pliku z rotacją. Zwraca True w przypadku sukcesu."""
        try:
            # Sprawdzenie czy logowanie do pliku jest włączone
            if not self.file_logging_enabled:
                return False

            if not self._ensure_log_directory():
                return False

            # Tworzenie pełnej ścieżki do pliku logu
            self.log_file = os.path.join(
                self.log_dir,
                f"{Logger.LOG_FILENAME_PREFIX}.log",
            )

            # Konfiguracja handlera pliku z rotacją dzienną
            self.file_handler = logging.handlers.TimedRotatingFileHandler(
                self.log_file,
                when="midnight",
                interval=1,
                backupCount=7,
                encoding="utf-8",
            )

            # Ustawienie formatera dla pliku
            file_formatter = logging.Formatter(
                Logger.FILE_FORMAT, datefmt=Logger.LOG_DATE_FORMAT
            )
            self.file_handler.setFormatter(file_formatter)

            # Dodanie handlera do loggera
            self.logger.addHandler(self.file_handler)

            return True
        except Exception as e:
            self.logger.error(
                f"Błąd podczas konfiguracji handlera pliku: {str(e)}",
                stacklevel=Logger.STACKLEVEL + 1,
            )
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
        """Ustawia tryb logowania. Zwraca True w przypadku sukcesu."""
        try:
            # Walidacja trybu
            if mode not in [
                Logger.LOG_MODE_NONE,
                Logger.LOG_MODE_INFO,
                Logger.LOG_MODE_DEBUG,
                Logger.LOG_MODE_CRITICAL,
                "ERROR",  # Dodanie obsługi trybu ERROR dla wstecznej kompatybilności
            ]:
                print(f"Nieznany tryb logowania: {mode}")
                return False

            # Obsługa trybu ERROR (mapowanie na tryb DEBUG)
            if mode == "ERROR":
                mode = Logger.LOG_MODE_DEBUG  # Traktuj ERROR tak samo jak DEBUG

            # Ustawienie trybu
            self.logging_mode = mode

            # Konfiguracja handlera konsoli
            if mode != Logger.LOG_MODE_NONE:
                if not self.console_handler:
                    if not self._configure_console_handler():
                        return False

                # Ustawienie poziomu logowania
                self._set_logging_level_for_mode(mode)

                # Dodaj specjalną obsługę dla trybu CRITICAL
                if mode == Logger.LOG_MODE_CRITICAL:
                    # Użyj specjalnych formaterów z datą/czasem
                    if self.console_handler:
                        self.console_handler.setFormatter(
                            LevelSpecificFormatter(
                                info_fmt=Logger.CONSOLE_FORMAT_INFO,
                                debug_fmt=Logger.CONSOLE_FORMAT_DEBUG,
                                warning_fmt=Logger.CONSOLE_FORMAT_WARNING_CRITICAL,
                                error_fmt=Logger.CONSOLE_FORMAT_ERROR_CRITICAL,
                                critical_fmt=Logger.CONSOLE_FORMAT_CRITICAL_CRITICAL,
                                datefmt=Logger.LOG_DATE_FORMAT,
                            )
                        )
                else:
                    # Standardowe formatery dla innych trybów
                    if self.console_handler:
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

            # Konfiguracja handlera pliku
            if (
                mode in [Logger.LOG_MODE_DEBUG, Logger.LOG_MODE_CRITICAL]
                and self.file_logging_enabled
            ):
                if not self.file_handler:
                    if not self._configure_file_handler():
                        self.logger.warning(
                            "Nie udało się skonfigurować logowania do pliku",
                            stacklevel=Logger.STACKLEVEL + 1,
                        )
            else:
                if self.file_handler:
                    self.logger.removeHandler(self.file_handler)
                    self.file_handler = None

            return True
        except Exception as e:
            print(f"Błąd podczas ustawiania trybu logowania: {str(e)}")
            return False

    def set_file_logging(self, enabled: bool) -> bool:
        """
        Włącza lub wyłącza logowanie do pliku.

        Args:
            enabled: True, aby włączyć logowanie do pliku; False, aby wyłączyć

        Returns:
            bool: True, jeśli operacja się powiodła; False w przeciwnym razie
        """
        if enabled == self.file_logging_enabled:
            return True  # Nic się nie zmienia

        old_state = self.file_logging_enabled
        self.file_logging_enabled = enabled

        # Loguj zmianę jako DEBUG (tylko do konsoli)
        if self.console_handler:
            self.logger.debug(
                f"Zmieniono logowanie do pliku z '{old_state}' na '{enabled}'",
                stacklevel=Logger.STACKLEVEL + 1,
            )

        # Aktualizuj handler pliku
        if enabled:
            if not self.file_handler:
                if not self._configure_file_handler():
                    self.file_logging_enabled = old_state  # Przywróć stary stan
                    if self.console_handler:
                        self.error(
                            "Nie udało się skonfigurować logowania do pliku.",
                            stacklevel=Logger.STACKLEVEL + 1,
                        )
                    return False
        else:
            if self.file_handler:
                if self.console_handler:
                    self.logger.debug(
                        "Wyłączanie logowania do pliku.",
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
        """
        if self.logging_mode in [Logger.LOG_MODE_NONE, Logger.LOG_MODE_INFO]:
            return  # Nie pokazuj DEBUG w trybie NONE ani INFO

        # Poprawne ustawienie stacklevel
        kwargs["stacklevel"] = kwargs.get("stacklevel", Logger.STACKLEVEL)
        append = kwargs.pop("append", False)

        if append:
            # Obsługa append
            if self.console_handler and isinstance(
                self.console_handler.stream, io.TextIOWrapper
            ):
                self.console_handler.stream.write(f"\r{message}")
                self.console_handler.stream.flush()
            else:
                print(f"\r{message}", end="", flush=True)
        else:
            self.logger.debug(message, *args, **kwargs)

    def info(self, message: str, *args: Any, **kwargs: Any) -> None:
        """
        Loguje wiadomość na poziomie INFO.

        Args:
            message: Wiadomość do zalogowania
            *args: Dodatkowe argumenty dla logger.info
            append: Jeśli True, dodaje wiadomość do poprzedniej linii bez nowej linii
            **kwargs: Dodatkowe argumenty słownikowe dla logger.info
        """
        if self.logging_mode == Logger.LOG_MODE_NONE:
            return

        # Tryb INFO pokazuje tylko wiadomości INFO
        if self.logging_mode == Logger.LOG_MODE_INFO:
            kwargs["stacklevel"] = kwargs.get("stacklevel", Logger.STACKLEVEL + 1)
            append = kwargs.pop("append", False)

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
                self.logger.info(message, *args, **kwargs)
        elif self.logging_mode in [Logger.LOG_MODE_DEBUG, Logger.LOG_MODE_CRITICAL]:
            # W innych trybach też pokazuj INFO
            kwargs["stacklevel"] = kwargs.get("stacklevel", Logger.STACKLEVEL + 1)
            append = kwargs.pop("append", False)

            if append:
                # Obsługa append jak wyżej
                if self.console_handler and isinstance(
                    self.console_handler.stream, io.TextIOWrapper
                ):
                    self.console_handler.stream.write(f"\r{message}")
                    self.console_handler.stream.flush()
                else:
                    print(f"\r{message}", end="", flush=True)
            else:
                self.logger.info(message, *args, **kwargs)

    def warning(self, message: str, *args: Any, **kwargs: Any) -> None:
        """
        Loguje wiadomość na poziomie WARNING.

        Args:
            message: Wiadomość do zalogowania
            *args: Dodatkowe argumenty dla logger.warning
            append: Jeśli True, dodaje wiadomość do poprzedniej linii bez nowej linii
            **kwargs: Dodatkowe argumenty słownikowe dla logger.warning
        """
        if self.logging_mode in [Logger.LOG_MODE_NONE, Logger.LOG_MODE_INFO]:
            return  # Nie pokazuj WARNING w trybie NONE ani INFO

        kwargs["stacklevel"] = kwargs.get("stacklevel", Logger.STACKLEVEL + 1)
        append = kwargs.pop("append", False)

        if append:
            # Obsługa append
            if self.console_handler and isinstance(
                self.console_handler.stream, io.TextIOWrapper
            ):
                self.console_handler.stream.write(f"\r{message}")
                self.console_handler.stream.flush()
            else:
                print(f"\r{message}", end="", flush=True)
        else:
            self.logger.warning(message, *args, **kwargs)

    def error(self, message: str, *args: Any, **kwargs: Any) -> None:
        """
        Loguje wiadomość na poziomie ERROR.

        Args:
            message: Wiadomość do zalogowania
            *args: Dodatkowe argumenty dla logger.error
            append: Jeśli True, dodaje wiadomość do poprzedniej linii bez nowej linii
            **kwargs: Dodatkowe argumenty słownikowe dla logger.error
        """
        if self.logging_mode in [Logger.LOG_MODE_NONE, Logger.LOG_MODE_INFO]:
            return  # Nie pokazuj ERROR w trybie NONE ani INFO

        kwargs["stacklevel"] = kwargs.get("stacklevel", Logger.STACKLEVEL + 1)
        append = kwargs.pop("append", False)

        if append:
            # Obsługa append
            if self.console_handler and isinstance(
                self.console_handler.stream, io.TextIOWrapper
            ):
                self.console_handler.stream.write(f"\r{message}")
                self.console_handler.stream.flush()
            else:
                print(f"\r{message}", end="", flush=True)
        else:
            self.logger.error(message, *args, **kwargs)

    def critical(self, message: str, *args: Any, **kwargs: Any) -> None:
        """
        Loguje wiadomość na poziomie CRITICAL.

        Args:
            message: Wiadomość do zalogowania
            *args: Dodatkowe argumenty dla logger.critical
            append: Jeśli True, dodaje wiadomość do poprzedniej linii bez nowej linii
            **kwargs: Dodatkowe argumenty słownikowe dla logger.critical
        """
        if self.logging_mode == Logger.LOG_MODE_NONE:
            return  # Nie pokazuj CRITICAL tylko w trybie NONE

        kwargs["stacklevel"] = kwargs.get("stacklevel", Logger.STACKLEVEL + 1)
        append = kwargs.pop("append", False)

        if append:
            # Obsługa append
            if self.console_handler and isinstance(
                self.console_handler.stream, io.TextIOWrapper
            ):
                self.console_handler.stream.write(f"\r{message}")
                self.console_handler.stream.flush()
            else:
                print(f"\r{message}", end="", flush=True)
        else:
            self.logger.critical(message, *args, **kwargs)

    def exception(self, message: str, *args: Any, **kwargs: Any) -> None:
        """
        Loguje wiadomość na poziomie ERROR z informacją o wyjątku.

        Args:
            message: Wiadomość do zalogowania
            *args: Dodatkowe argumenty dla logger.exception
            append: Jeśli True, dodaje wiadomość do poprzedniej linii bez nowej linii
            **kwargs: Dodatkowe argumenty słownikowe dla logger.exception
        """
        if self.logging_mode == Logger.LOG_MODE_NONE:
            return

        kwargs["stacklevel"] = kwargs.get("stacklevel", Logger.STACKLEVEL + 1)
        append = kwargs.pop("append", False)

        if self.logger.isEnabledFor(logging.ERROR):
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
                self.logger.exception(message, *args, **kwargs)


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
        self.formatters = {}

        # Upewnij się, że wszystkie formaty są prawidłowo ustawione
        if info_fmt:
            self.formatters[logging.INFO] = logging.Formatter(
                fmt=info_fmt, datefmt=datefmt
            )
        if debug_fmt:
            self.formatters[logging.DEBUG] = logging.Formatter(
                fmt=debug_fmt, datefmt=datefmt
            )
        if warning_fmt:
            self.formatters[logging.WARNING] = logging.Formatter(
                fmt=warning_fmt, datefmt=datefmt
            )
        if error_fmt:
            self.formatters[logging.ERROR] = logging.Formatter(
                fmt=error_fmt, datefmt=datefmt
            )
        if critical_fmt:
            self.formatters[logging.CRITICAL] = logging.Formatter(
                fmt=critical_fmt, datefmt=datefmt
            )

        # Format domyślny dla poziomów, które nie mają zdefiniowanego formatu
        self.default_formatter = logging.Formatter(
            fmt=info_fmt or "%(message)s", datefmt=datefmt
        )

    def format(self, record):
        formatter = self.formatters.get(record.levelno, self.default_formatter)
        return formatter.format(record)


# Eksport klasy Logger
__all__ = ["Logger"]
