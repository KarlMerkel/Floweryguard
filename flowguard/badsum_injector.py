"""Модуль инъекции пакетов с битой контрольной суммой (Bad Checksum Injection).

Реализация техники обхода DPI:
- При Fake SNI Desync фейковый пакет ClientHello или STUN отправляется с заведомо
  неверной контрольной суммой TCP/IP (или UDP).
- Физический механизм:
  1. Реальный сервер назначения (сетевой адаптер NIC с аппаратным Checksum Offload
     или стек TCP/IP ОС) мгновенно отбрасывает пакет на канальном/сетевом уровне
     согласно RFC 793 / RFC 1122 без передачи в сокет приложения и БЕЗ отправки RST.
  2. Пассивный ТСПУ-инспектор (DPI), зеркалирующий оптический поток на скорости
     100+ Гбит/с, в подавляющем большинстве реализаций контрольные суммы НЕ проверяет
     (слишком дорого в плане ресурсов процессора/FPGA).
  3. В результате DPI переключает контекст сессии на фейковый SNI/домен, а целевой
     сервер соединения не разрывает.
  4. В комбинации с TTL (autottl) обеспечивает максимальную устойчивость против
     как пассивного (зеркального), так и активного (in-line) DPI.
"""

import os
import sys
import time
import socket
import struct
import ctypes
import threading
from typing import Optional

try:
    from Floweryguard.logger import get_logger
except ImportError:
    from flowguard.logger import get_logger

logger = get_logger("BadsumInjector")


def calc_ip_checksum(data: bytes) -> int:
    """Вычисляет 16-битную контрольную сумму (RFC 1071 One's Complement Sum)."""
    if len(data) % 2 == 1:
        data += b"\x00"
    s = sum((data[i] << 8) + data[i + 1] for i in range(0, len(data), 2))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


def calc_tcp_checksum(src_ip: str, dst_ip: str, tcp_segment: bytes) -> int:
    """Вычисляет контрольную сумму TCP с псевдозаголовком IPv4."""
    try:
        src_bytes = socket.inet_aton(src_ip)
        dst_bytes = socket.inet_aton(dst_ip)
    except Exception:
        return 0
    pseudo_hdr = src_bytes + dst_bytes + struct.pack("!BBH", 0, socket.IPPROTO_TCP, len(tcp_segment))
    c = calc_ip_checksum(pseudo_hdr + tcp_segment)
    return 0xFFFF if c == 0 else c


def calc_udp_checksum(src_ip: str, dst_ip: str, udp_segment: bytes) -> int:
    """Вычисляет контрольную сумму UDP с псевдозаголовком IPv4."""
    try:
        src_bytes = socket.inet_aton(src_ip)
        dst_bytes = socket.inet_aton(dst_ip)
    except Exception:
        return 0
    pseudo_hdr = src_bytes + dst_bytes + struct.pack("!BBH", 0, socket.IPPROTO_UDP, len(udp_segment))
    c = calc_ip_checksum(pseudo_hdr + udp_segment)
    return 0xFFFF if c == 0 else c


def corrupt_checksum(valid_checksum: int, xor_mask: int = 0x1234) -> int:
    """Намеренно портит контрольную сумму (Badsum Trick).
    
    Гарантирует, что итоговая сумма:
    1. Не совпадает с оригинальной валидной суммой.
    2. Не равна 0x0000 (в UDP 0x0000 означает «чексумма отключена»).
    3. Приведет к гарантированному сбросу пакета на удаленном NIC.
    """
    corrupted = (valid_checksum ^ xor_mask) & 0xFFFF
    if corrupted == valid_checksum:
        corrupted = (corrupted ^ 0x55AA) & 0xFFFF
    if corrupted == 0:
        corrupted = 0xDEAD
    return corrupted


def craft_fake_tcp_segment(
    src_ip: str,
    dst_ip: str,
    src_port: int,
    dst_port: int,
    seq: int,
    ack: int,
    payload: bytes,
    flags: int = 0x18,  # PSH + ACK
    window: int = 65535,
    corrupt_sum: bool = True,
    xor_mask: int = 0x1234,
) -> bytes:
    """Формирует TCP сегмент с опционально испорченной контрольной суммой (badsum)."""
    data_offset = 5  # 5 слов по 32 бита = 20 байт
    offset_reserved = (data_offset << 4) & 0xF0
    urg_ptr = 0

    # Заголовок с нулевой контрольной суммой для расчета
    tcp_hdr_zero = struct.pack(
        "!HHIIBBHHH",
        src_port,
        dst_port,
        seq,
        ack,
        offset_reserved,
        flags,
        window,
        0,
        urg_ptr,
    )
    raw_segment = tcp_hdr_zero + payload
    real_cksum = calc_tcp_checksum(src_ip, dst_ip, raw_segment)

    final_cksum = corrupt_checksum(real_cksum, xor_mask) if corrupt_sum else real_cksum

    tcp_hdr = struct.pack(
        "!HHIIBBHHH",
        src_port,
        dst_port,
        seq,
        ack,
        offset_reserved,
        flags,
        window,
        final_cksum,
        urg_ptr,
    )
    return tcp_hdr + payload


def craft_fake_ipv4_packet(
    src_ip: str,
    dst_ip: str,
    transport_payload: bytes,
    protocol: int = socket.IPPROTO_TCP,
    ttl: int = 64,
    identification: int = 54321,
    corrupt_ip_sum: bool = False,
) -> bytes:
    """Формирует полный IPv4 пакет с указанным TTL и транспортным сегментом."""
    version_ihl = (4 << 4) | 5
    tos = 0
    total_len = 20 + len(transport_payload)
    flags_frag = 0x4000  # DF (Don't Fragment)
    src_bytes = socket.inet_aton(src_ip)
    dst_bytes = socket.inet_aton(dst_ip)

    ip_hdr_zero = struct.pack(
        "!BBHHHBBH4s4s",
        version_ihl,
        tos,
        total_len,
        identification,
        flags_frag,
        ttl,
        protocol,
        0,
        src_bytes,
        dst_bytes,
    )
    real_ip_sum = calc_ip_checksum(ip_hdr_zero)
    final_ip_sum = corrupt_checksum(real_ip_sum) if corrupt_ip_sum else real_ip_sum

    ip_hdr = struct.pack(
        "!BBHHHBBH4s4s",
        version_ihl,
        tos,
        total_len,
        identification,
        flags_frag,
        ttl,
        protocol,
        final_ip_sum,
        src_bytes,
        dst_bytes,
    )
    return ip_hdr + transport_payload


class WinDivertAddress(ctypes.Structure):
    """Структура WINDIVERT_ADDRESS (WinDivert 2.x, 80 байт)."""
    _fields_ = [
        ("Timestamp", ctypes.c_int64),
        ("Bitfields", ctypes.c_uint32),
        ("Reserved2", ctypes.c_uint32),
        ("Data", ctypes.c_uint8 * 64),
    ]


class WinDivertBadsumController:
    """Контроллер прямого взаимодействия с WinDivert.dll для пакетного внедрения badsum.
    
    Работает через ctypes, загружая WinDivert.dll из каталога zapret_bin.
    Thread-safe: все операции с дескриптором WinDivert защищены _lock.
    """

    def __init__(self, dll_path: Optional[str] = None):
        self.dll_path = dll_path
        self._dll: Optional[ctypes.WinDLL] = None
        self._is_available: bool = False
        self._handle: Optional[int] = None
        self._lock = threading.Lock()
        self._init_dll()

    def _init_dll(self) -> None:
        if sys.platform != "win32":
            return
        if not self.dll_path:
            try:
                try:
                    from Floweryguard.config import get_app_base_dir
                except ImportError:
                    from flowguard.config import get_app_base_dir
            except ImportError:
                def get_app_base_dir():
                    if getattr(sys, "frozen", False):
                        return os.path.dirname(sys.executable)
                    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            base_dir = get_app_base_dir()
            candidate = os.path.join(base_dir, "zapret_bin", "WinDivert.dll")
            if os.path.exists(candidate):
                self.dll_path = candidate
            else:
                alt_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
                alt_candidate = os.path.join(alt_dir, "zapret_bin", "WinDivert.dll")
                if os.path.exists(alt_candidate):
                    self.dll_path = alt_candidate

        if self.dll_path and os.path.exists(self.dll_path):
            try:
                self._dll = ctypes.WinDLL(self.dll_path)

                # WinDivertOpen(const char *filter, WINDIVERT_LAYER layer, INT16 priority, UINT64 flags)
                self._dll.WinDivertOpen.argtypes = [ctypes.c_char_p, ctypes.c_int, ctypes.c_int16, ctypes.c_uint64]
                self._dll.WinDivertOpen.restype = ctypes.c_void_p

                # WinDivertSend(HANDLE handle, const VOID *pPacket, UINT packetLen, UINT *pSendLen, const WINDIVERT_ADDRESS *pAddr)
                self._dll.WinDivertSend.argtypes = [
                    ctypes.c_void_p,
                    ctypes.c_void_p,
                    ctypes.c_uint,
                    ctypes.POINTER(ctypes.c_uint),
                    ctypes.c_void_p,
                ]
                self._dll.WinDivertSend.restype = ctypes.c_bool

                # WinDivertClose(HANDLE handle)
                self._dll.WinDivertClose.argtypes = [ctypes.c_void_p]
                self._dll.WinDivertClose.restype = ctypes.c_bool

                self._is_available = True
                logger.info("WinDivert.dll успешно обнаружен и инициализирован для direct badsum")
            except Exception as e:
                logger.debug(f"Не удалось загрузить WinDivert.dll ({e})")
                self._is_available = False

    @property
    def is_available(self) -> bool:
        return self._is_available

    def open_injection_handle(self) -> bool:
        """Открывает дескриптор WinDivert для инъекции пакетов без перехвата стороннего трафика (filter='false').

        ВАЖНО: НЕ открываем второй handle если winws.exe уже держит WinDivert64.sys в ядре.
        Два handle к одному ядерному драйверу вызывают BSOD (DRIVER_IRQL_NOT_LESS_OR_EQUAL).

        Thread-safe: защищено _lock для предотвращения одновременного вызова из нескольких потоков прокси.
        """
        if not self._is_available or self._dll is None:
            return False

        with self._lock:
            if self._handle is not None and self._handle not in (0, -1, 0xFFFFFFFFFFFFFFFF):
                return True

            # --- BSOD Protection: конфликт с запущенным winws.exe / zapret ---
            # winws.exe уже держит WinDivert64.sys открытым с фильтром UDP портов.
            # Открытие второго handle из Python через ctypes вызывает конфликт
            # в ядерном драйвере, что приводит к BSOD. Безопасный обход — полностью
            # пропустить WinDivertOpen при активном winws и вернуть False (graceful degradation).
            #
            # ВАЖНО: проверяем дважды с паузой, т.к. winws.exe может стартовать параллельно
            # через VoiceHelper.start() и ещё не успеть появиться в tasklist.
            for attempt in range(2):
                try:
                    import subprocess
                    creationflags = subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
                    out = subprocess.check_output(
                        ["tasklist", "/FI", "IMAGENAME eq winws.exe", "/NH"],
                        creationflags=creationflags,
                        timeout=3,
                    )
                    if b"winws.exe" in out.lower():
                        logger.debug(
                            "WinDivert badsum injection отключена: winws.exe уже держит WinDivert64.sys. "
                            "Открытие второго handle вызовет BSOD — пропускаем."
                        )
                        return False
                except Exception as te:
                    logger.debug("tasklist winws check failed: %s", te)
                # Пауза перед повторной проверкой — winws.exe мог стартовать в гонке
                if attempt == 0:
                    time.sleep(0.5)

            # Дополнительная проверка: если драйвер WinDivert уже загружен в ядро
            # (даже если winws.exe не виден в tasklist), безопаснее не открывать handle
            try:
                import subprocess
                creationflags = subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
                sc_out = subprocess.check_output(
                    ["sc", "query", "WinDivert"],
                    creationflags=creationflags,
                    timeout=2,
                    stderr=subprocess.DEVNULL,
                )
                if b"RUNNING" in sc_out:
                    logger.debug(
                        "WinDivert драйвер уже запущен в ядре (sc query WinDivert → RUNNING). "
                        "Пропускаем WinDivertOpen во избежание BSOD."
                    )
                    return False
            except Exception as sce:
                logger.debug("sc query WinDivert check failed: %s", sce)

            try:
                # Слой WINDIVERT_LAYER_NETWORK = 0, priority = 0, flags = 0
                handle = self._dll.WinDivertOpen(b"false", 0, 0, 0)
                if handle is None or handle in (0, -1, 0xFFFFFFFFFFFFFFFF):
                    err = ctypes.GetLastError()
                    logger.debug(f"WinDivertOpen вернул INVALID_HANDLE_VALUE (ошибка {err}). Инъекция badsum отключена.")
                    self._handle = None
                    return False
                self._handle = handle
                logger.info("Дескриптор WinDivert успешно открыт для direct injection")
                return True
            except Exception as e:
                logger.debug(f"Ошибка при вызове WinDivertOpen: {e}")
                self._handle = None
                return False

    def close(self) -> None:
        """Закрывает открытый дескриптор WinDivert."""
        with self._lock:
            if self._handle is not None and self._dll is not None:
                try:
                    self._dll.WinDivertClose(self._handle)
                except Exception as ce:
                    logger.debug("WinDivertClose failed: %s", ce)
                self._handle = None

    def inject_packet(self, raw_packet: bytes) -> bool:
        """Инжектирует сырой IPv4/TCP пакет напрямую в исходящий сетевой стек Windows."""
        if not self._is_available or self._dll is None:
            return False
        if self._handle is None or self._handle in (0, -1, 0xFFFFFFFFFFFFFFFF):
            if not self.open_injection_handle():
                return False

        try:
            addr = WinDivertAddress()
            addr.Timestamp = 0
            # Бит 17 (Outbound = 1) -> 1 << 17
            addr.Bitfields = (1 << 17)
            addr.Reserved2 = 0

            packet_len = len(raw_packet)
            packet_buf = ctypes.create_string_buffer(raw_packet, packet_len)
            send_len = ctypes.c_uint(0)

            res = self._dll.WinDivertSend(
                self._handle,
                packet_buf,
                packet_len,
                ctypes.byref(send_len),
                ctypes.byref(addr),
            )
            return bool(res)
        except Exception as e:
            logger.debug(f"Исключение при вызове WinDivertSend: {e}")
            return False

    def inject_fake_sni_packet(
        self,
        sock: socket.socket,
        fake_payload: bytes,
        corrupt_sum: bool = True,
        ttl: int = 64,
        seq: Optional[int] = None,
        ack: Optional[int] = None,
    ) -> bool:
        """Формирует и инжектирует фейковый TCP сегмент (Badsum/AutoTTL) для существующего сокета.
        
        АРХИТЕКТУРНОЕ ПРИМЕЧАНИЕ О TCP SEQUENCE/ACK:
        - В пассивных DPI (ТСПУ / зеркало оптического потока) инспекторы работают stateless
          (без поддержания таблиц скользящего окна SEQ/ACK на 100 Гбит/с интерфейсах) —
          пакет с битой чексуммой захватывается инспектором и сбивает фильтр вне зависимости от seq.
        - Если инспектор stateful (отслеживает фазу окна после 3-way handshake), произвольный seq
          может быть отброшен как out-of-window. В Flowery для 100% обхода stateful DPI реализована
          интеграция zapret (winws.exe) через VoiceHelper, где WinDivert перехватывает реальные пакеты 
          ядра и инжектирует badsum с точным соответствием реальных tcp.SeqNum / tcp.AckNum.
        - Данный метод позволяет явно передавать реальные seq/ack (если известны) или генерирует
          псевдослучайный ISN вместо константы 1000.
        """
        try:
            src_ip, src_port = sock.getsockname()[:2]
            dst_ip, dst_port = sock.getpeername()[:2]
        except Exception as e:
            logger.debug(f"Не удалось получить адреса сокета для Badsum инъекции: {e}")
            return False

        # Безопасная обработка сокетов IPv6 (AF_INET6): badsum инъекция рассчитана на IPv4 (B18)
        if getattr(sock, "family", None) == socket.AF_INET6 or ":" in str(src_ip) or ":" in str(dst_ip):
            logger.debug("Badsum injection skipped for AF_INET6 socket (IPv4 only)")
            return False

        if seq is None:
            # Псевдослучайный 32-битный ISN в допустимом пространстве номеров последовательности
            seq = (int(time.time() * 1000) ^ (src_port << 16)) & 0x7FFFFFFF
        if ack is None:
            ack = 0

        try:
            tcp_seg = craft_fake_tcp_segment(
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                seq=seq,
                ack=ack,
                payload=fake_payload,
                corrupt_sum=corrupt_sum,
            )
            ipv4_pkt = craft_fake_ipv4_packet(
                src_ip=src_ip,
                dst_ip=dst_ip,
                transport_payload=tcp_seg,
                ttl=ttl,
            )
            return self.inject_packet(ipv4_pkt)
        except Exception as e:
            logger.debug(f"Ошибка при сборке и инъекции фейкового SNI пакета: {e}")
            return False

    inject_fake_packet = inject_fake_sni_packet

    def corrupt_packet_tcp_checksum(self, packet_bytes: bytearray, ip_hdr_len: int = 20) -> bytearray:
        """Портит TCP контрольную сумму в сыром пакете IPv4."""
        if len(packet_bytes) < ip_hdr_len + 20:
            return packet_bytes
        # Чексумма TCP находится со смещением 16 байт от начала TCP заголовка
        cksum_offset = ip_hdr_len + 16
        current_cksum = struct.unpack("!H", packet_bytes[cksum_offset : cksum_offset + 2])[0]
        bad = corrupt_checksum(current_cksum, 0x1234)
        packet_bytes[cksum_offset : cksum_offset + 2] = struct.pack("!H", bad)
        return packet_bytes

    def __del__(self):
        self.close()


_GLOBAL_BADSUM_CONTROLLER: Optional[WinDivertBadsumController] = None


def get_badsum_controller() -> WinDivertBadsumController:
    """Возвращает глобальный синглтон WinDivertBadsumController."""
    global _GLOBAL_BADSUM_CONTROLLER
    if _GLOBAL_BADSUM_CONTROLLER is None:
        _GLOBAL_BADSUM_CONTROLLER = WinDivertBadsumController()
    return _GLOBAL_BADSUM_CONTROLLER
