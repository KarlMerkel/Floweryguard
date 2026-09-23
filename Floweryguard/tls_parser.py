"""Парсер TLS ClientHello и генератор фрагментов TLS Record.
Используется для точечного определения SNI и разбиения TLS-записей.
Строго стандартная библиотека Python.
"""

import struct
from typing import Optional, Tuple, List


def is_tls_client_hello(data: bytes) -> bool:
    """Проверяет, является ли пакет TLS ClientHello."""
    if len(data) < 9:
        return False
    # Content Type: 0x16 (Handshake), Version: 0x03 0x00..0x04
    if data[0] != 0x16 or data[1] != 0x03:
        return False
    # Handshake Type: 0x01 (ClientHello)
    if data[5] != 0x01:
        return False
    return True


def parse_sni(data: bytes) -> Optional[Tuple[str, int, int]]:
    """Извлекает SNI (Server Name Indication) из пакета ClientHello.
    
    Возвращает кортеж: (hostname, start_pos_in_data, length_of_sni)
    или None, если SNI не найден.
    """
    if not is_tls_client_hello(data):
        return None

    try:
        # TLS Record Header (5 байт)
        # data[0]: 0x16, data[1:3]: version, data[3:5]: record_length
        pos = 43
        if pos >= len(data):
            return None

        # Session ID
        session_id_len = data[pos]
        pos += 1 + session_id_len
        if pos + 2 > len(data):
            return None

        # Cipher Suites
        cipher_suites_len = struct.unpack("!H", data[pos:pos + 2])[0]
        pos += 2 + cipher_suites_len
        if pos >= len(data):
            return None

        # Compression Methods
        comp_methods_len = data[pos]
        pos += 1 + comp_methods_len
        if pos + 2 > len(data):
            return None

        # Extensions
        extensions_len = struct.unpack("!H", data[pos:pos + 2])[0]
        pos += 2
        ext_end = min(pos + extensions_len, len(data))

        while pos + 4 <= ext_end:
            ext_type = struct.unpack("!H", data[pos:pos + 2])[0]
            ext_data_len = struct.unpack("!H", data[pos + 2:pos + 4])[0]
            pos += 4

            if ext_type == 0x0000:  # Server Name Extension (SNI)
                if pos + ext_data_len > len(data):
                    return None
                sni_data = data[pos:pos + ext_data_len]
                if len(sni_data) < 5:
                    return None
                sn_type = sni_data[2]
                if sn_type == 0:  # host_name
                    name_len = struct.unpack("!H", sni_data[3:5])[0]
                    host_start = pos + 5
                    if host_start + name_len <= len(data):
                        host_bytes = data[host_start:host_start + name_len]
                        try:
                            hostname = host_bytes.decode("idna")
                            return (hostname, host_start, name_len)
                        except Exception:
                            try:
                                hostname = host_bytes.decode("utf-8", errors="replace")
                                return (hostname, host_start, name_len)
                            except Exception:
                                return None
            pos += ext_data_len

        return None
    except Exception:
        return None


def get_sni_offsets(data: bytes) -> Optional[Tuple[int, int, int]]:
    """Возвращает точные смещения SNI в пакете ClientHello:
    (sni_start, sni_mid, sni_end).
    
    - sni_start (+s): позиция первого байта имени хоста.
    - sni_mid (+sm): позиция середины имени хоста.
    - sni_end (+se): позиция последнего байта имени хоста.
    """
    info = parse_sni(data)
    if not info:
        return None
    _, start, length = info
    mid = start + max(1, length // 2)
    end = start + length
    return (start, mid, end)


def create_tls_record_fragments(data: bytes, split_offset: Optional[int] = None) -> List[bytes]:
    """Разбивает один ClientHello TLS Record на два валидных TLS Record.
    
    Каждый фрагмент получает собственный корректный 5-байтный заголовок TLS Record.
    Это техника TLS Record Fragmentation (известная по ByeDPI и zapret tpws).
    """
    if not is_tls_client_hello(data) or len(data) < 10:
        return [data]

    rec_version = data[1:3]
    payload = data[5:]

    if split_offset is None:
        sni_info = parse_sni(data)
        if sni_info:
            split_point = sni_info[1] - 5 + 1
        else:
            split_point = min(40, len(payload) // 2)
    else:
        split_point = max(1, min(split_offset - 5, len(payload) - 1))

    if split_point <= 0 or split_point >= len(payload):
        return [data]

    payload1 = payload[:split_point]
    payload2 = payload[split_point:]

    rec1 = b"\x16" + rec_version + struct.pack("!H", len(payload1)) + payload1
    rec2 = b"\x16" + rec_version + struct.pack("!H", len(payload2)) + payload2

    return [rec1, rec2]


def create_multi_tls_record_fragments(data: bytes, split_offsets: Optional[List[int]] = None) -> List[bytes]:
    """Разбивает один ClientHello на N валидных TLS Record (каскадная фрагментация).
    
    Каждый срез получает стандартный TLS Record Header (RFC 5246/8446).
    """
    if not is_tls_client_hello(data) or len(data) < 15:
        return [data]

    rec_version = data[1:3]
    payload = data[5:]
    payload_len = len(payload)

    if not split_offsets:
        # Автоматические точки разбиения: SNI-start, SNI-mid, если найдены
        offsets = get_sni_offsets(data)
        if offsets:
            start, mid, _ = offsets
            points = [start - 5, mid - 5]
        else:
            points = [payload_len // 3, (2 * payload_len) // 3]
    else:
        # Преобразуем смещения пакета в смещения payload (минус 5 байт заголовка)
        points = [max(1, min(p - 5 if p > 5 else p, payload_len - 1)) for p in split_offsets]

    # Сортируем и удаляем дубликаты
    sorted_points = sorted(list(set(points)))
    valid_points = [p for p in sorted_points if 0 < p < payload_len]

    if not valid_points:
        return [data]

    records = []
    prev = 0
    for p in valid_points:
        chunk = payload[prev:p]
        if chunk:
            rec = b"\x16" + rec_version + struct.pack("!H", len(chunk)) + chunk
            records.append(rec)
        prev = p

    last_chunk = payload[prev:]
    if last_chunk:
        rec = b"\x16" + rec_version + struct.pack("!H", len(last_chunk)) + last_chunk
        records.append(rec)

    return records if len(records) > 1 else [data]


def create_dummy_tls_record(dummy_type: str = "alert") -> bytes:
    """Генерирует минимальный безобидный TLS Record для сбивания анализаторов DPI.
    
    - 'alert': TLS Alert (Level=Warning, Description=CloseNotify, RFC 5246 7.2.1)
    - 'appdata': Пустой TLS Application Data Record (Content Type 0x17)
    """
    if dummy_type == "appdata":
        # Content Type 0x17 (Application Data), Version TLS 1.2, Length 0
        return b"\x17\x03\x03\x00\x00"
    else:
        # Content Type 0x15 (Alert), Version TLS 1.2, Length 2, Warning(1), CloseNotify(0)
        return b"\x15\x03\x03\x00\x02\x01\x00"
