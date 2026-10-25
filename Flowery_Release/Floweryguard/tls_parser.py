"""Парсер TLS ClientHello и генератор фрагментов TLS Record.
Используется для точечного определения SNI и разбиения TLS-записей.
Строго стандартная библиотека Python.
"""

import logging
import struct
from typing import Optional, Tuple, List

logger = logging.getLogger("Flowery.TLSParser")


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

            if pos + ext_data_len > ext_end:
                return None

            if ext_type == 0x0000:  # Server Name Extension (SNI)
                sni_data = data[pos:pos + ext_data_len]
                if len(sni_data) < 5:
                    return None
                sn_type = sni_data[2]
                if sn_type == 0:  # host_name
                    name_len = struct.unpack("!H", sni_data[3:5])[0]
                    if 5 + name_len > len(sni_data):
                        return None
                    host_start = pos + 5
                    if host_start + name_len <= ext_end:
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
    except Exception as e:
        logger.debug("parse_sni encountered parse error: %s", e)
        return None


def get_sni_offsets(data: bytes) -> Optional[Tuple[int, int, int]]:
    """Возвращает точные смещения SNI в пакете ClientHello:
    (sni_start, sni_mid, sni_end).
    
    - sni_start (+s): позиция первого байта имени хоста.
    - sni_mid (+sm): позиция середины имени хоста (в середине SLD для мультиуровневых доменов).
    - sni_end (+se): позиция последнего байта имени хоста.
    """
    info = parse_sni(data)
    if not info or info[2] <= 0:
        return None
    _, start, length = info
    end = start + length

    # Работаем строго с сырыми байтами имени хоста в пакете data,
    # чтобы смещения гарантированно совпадали с физическими байтами буфера,
    # включая Punycode (IDNA) и произвольные кодировки.
    host_bytes = data[start:end]
    clean_host = host_bytes.rstrip(b".")
    parts = clean_host.split(b".")

    if len(parts) >= 2:
        # Учитываем составные ccTLD (.co.uk, .gov.ru, .com.ru, .org.ru и др.)
        common_2nd_tlds = {b"co", b"com", b"net", b"org", b"gov", b"edu", b"mil", b"ac"}
        if len(parts) >= 3 and len(parts[-1]) == 2 and parts[-2].lower() in common_2nd_tlds:
            sld_idx = len(parts) - 3
        else:
            sld_idx = len(parts) - 2

        sld = parts[sld_idx]
        sld_start = len(b".".join(parts[:sld_idx])) + 1 if sld_idx > 0 else 0
        mid_offset = sld_start + max(1, len(sld) // 2)
        mid = start + mid_offset
    else:
        mid = start + max(1, len(clean_host) // 2)

    mid = min(end - 1, max(start + 1, mid))
    return (start, mid, end)


def randomize_sni_case(data: bytes) -> bytes:
    """Рандомизирует регистр символов домена SNI в TLS ClientHello (например, dIsCoRd.cOm).
    
    RFC 6066 указывает, что доменные имена регистронезависимы, поэтому серверы
    (Cloudflare, Google, Discord) парсят их штатно, а сигнатурные парсеры ТСПУ,
    проверяющие точные строковые паттерны в нижнем регистре, пропускают трафик.
    """
    offsets = get_sni_offsets(data)
    if not offsets:
        return data
    start, _, end = offsets
    sni_bytes = bytearray(data[start:end])
    for i in range(len(sni_bytes)):
        b = sni_bytes[i]
        # Буквы латинского алфавита a-z, A-Z
        if (65 <= b <= 90) or (97 <= b <= 122):
            if i % 2 == 1:
                sni_bytes[i] = b ^ 0x20
    return data[:start] + bytes(sni_bytes) + data[end:]


def create_tls_record_fragments(data: bytes, split_offset: Optional[int] = None) -> List[bytes]:
    """Разбивает один ClientHello TLS Record на два валидных TLS Record.
    
    Каждый фрагмент получает собственный корректный 5-байтный заголовок TLS Record.
    Это техника TLS Record Fragmentation (известная по ByeDPI и zapret tpws).
    """
    if not is_tls_client_hello(data) or len(data) < 10:
        return [data]

    rec_len = struct.unpack("!H", data[3:5])[0]
    total_rec_len = 5 + rec_len
    if len(data) < total_rec_len:
        return [data]

    rec_version = data[1:3]
    payload = data[5:total_rec_len]
    tail = data[total_rec_len:]

    if split_offset is None:
        offsets = get_sni_offsets(data)
        if offsets:
            split_point = max(1, min(offsets[1] - 5, len(payload) - 1))
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

    if tail:
        return [rec1, rec2 + tail]
    return [rec1, rec2]


def create_multi_tls_record_fragments(data: bytes, split_offsets: Optional[List[int]] = None) -> List[bytes]:
    """Разбивает один ClientHello на N валидных TLS Record (каскадная фрагментация).
    
    Каждый срез получает стандартный TLS Record Header (RFC 5246/8446).
    """
    if not is_tls_client_hello(data) or len(data) < 15:
        return [data]

    rec_len = struct.unpack("!H", data[3:5])[0]
    total_rec_len = 5 + rec_len
    if len(data) < total_rec_len:
        return [data]

    rec_version = data[1:3]
    payload = data[5:total_rec_len]
    tail = data[total_rec_len:]
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
        if tail:
            rec += tail
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


ECH_EXTENSION_TYPES = {
    0xFE0D,  # Encrypted Client Hello (ECH) draft-ietf-tls-esni-13+
    0xFF02,  # Encrypted Server Name Indication (legacy ESNI)
    0xFD00,  # Outer Extensions (ECH draft extension used in inner/outer hello)
}

TLS_PADDING_EXTENSION_TYPE = 0x0015  # RFC 7685 TLS Padding Extension


def _parse_extensions_info(data: bytes) -> Optional[Tuple[int, int, List[Tuple[int, int, int]]]]:
    """Вспомогательная функция для парсинга блока расширений TLS ClientHello.
    
    Возвращает:
      (ext_len_pos, extensions_len, list_of_(ext_type, ext_start, ext_total_len))
      или None при ошибке структуры.
    """
    if not is_tls_client_hello(data) or len(data) < 45:
        return None
    try:
        # TLS Record Header (5 байт) + Handshake Header (4 байта) + Client Version (2 байта) + Random (32 байта) = 43 байта
        pos = 43
        session_id_len = data[pos]
        pos += 1 + session_id_len
        if pos + 2 > len(data):
            return None
        cipher_suites_len = struct.unpack("!H", data[pos:pos + 2])[0]
        pos += 2 + cipher_suites_len
        if pos >= len(data):
            return None
        comp_methods_len = data[pos]
        pos += 1 + comp_methods_len
        if pos + 2 > len(data):
            return None

        ext_len_pos = pos
        extensions_len = struct.unpack("!H", data[pos:pos + 2])[0]
        pos += 2
        ext_end = min(pos + extensions_len, len(data))

        extensions = []
        while pos + 4 <= ext_end:
            ext_type = struct.unpack("!H", data[pos:pos + 2])[0]
            ext_data_len = struct.unpack("!H", data[pos + 2:pos + 4])[0]
            total_len = 4 + ext_data_len
            if pos + total_len > ext_end:
                break
            extensions.append((ext_type, pos, total_len))
            pos += total_len

        return ext_len_pos, extensions_len, extensions
    except Exception as e:
        logger.debug("_parse_extensions_info encountered parse error: %s", e)
        return None


def strip_ech_from_client_hello(data: bytes) -> bytes:
    """Удаляет расширения Encrypted Client Hello (ECH) и ESNI (0xfe0d, 0xff02, 0xfd00)
    из пакета TLS ClientHello, принудительно возвращая серверы (Cloudflare и др.)
    к обработке открытого SNI.
    
    Это предотвращает сбросы (RST/Drop) соединений ТСПУ, которые блокируют ECH-трафик
    из-за невозможности инспекции шифрованного имени хоста.
    """
    info = _parse_extensions_info(data)
    if not info:
        return data

    ext_len_pos, old_ext_len, extensions = info
    has_ech = any(ext_type in ECH_EXTENSION_TYPES for ext_type, _, _ in extensions)
    if not has_ech:
        return data

    try:
        new_ext_bytes = bytearray()
        for ext_type, start, total_len in extensions:
            if ext_type not in ECH_EXTENSION_TYPES:
                new_ext_bytes.extend(data[start:start + total_len])

        new_ext_len = len(new_ext_bytes)
        diff = old_ext_len - new_ext_len

        # Обновление длины TLS Record (2 байта по смещению 3:5)
        old_rec_len = struct.unpack("!H", data[3:5])[0]
        new_rec_len = max(0, old_rec_len - diff)

        # Обновление длины Handshake ClientHello (3 байта по смещению 6:9)
        old_hs_len = int.from_bytes(data[6:9], "big")
        new_hs_len = max(0, old_hs_len - diff)

        # Сборка модифицированного TLS ClientHello
        new_data = (
            data[:3]
            + struct.pack("!H", new_rec_len)
            + data[5:6]
            + new_hs_len.to_bytes(3, "big")
            + data[9:ext_len_pos]
            + struct.pack("!H", new_ext_len)
            + bytes(new_ext_bytes)
            + data[ext_len_pos + 2 + old_ext_len:]
        )
        return new_data
    except Exception as e:
        logger.warning("strip_ech_from_client_hello failed: %s", e)
        return data


def inject_tls_padding(data: bytes, target_size: int = 1250) -> bytes:
    """Добавляет расширение TLS Padding (RFC 7685, Type 0x0015) в ClientHello
    для увеличения размера пакета до target_size (по умолчанию 1250 байт).
    
    Техника переполняет входные кольцевые буферы DPI/ТСПУ и искажает
    ожидаемые сигнатурные размеры пакетов, предотвращая детекцию на лету.
    """
    if not is_tls_client_hello(data) or len(data) >= target_size:
        return data

    info = _parse_extensions_info(data)
    if not info:
        return data

    ext_len_pos, old_ext_len, extensions = info

    try:
        needed_bytes = target_size - len(data)
        if needed_bytes <= 0:
            return data

        # Проверяем, есть ли уже существующее расширение padding (0x0015)
        existing_pad_idx = -1
        for idx, (ext_type, start, total_len) in enumerate(extensions):
            if ext_type == TLS_PADDING_EXTENSION_TYPE:
                existing_pad_idx = idx
                break

        if existing_pad_idx != -1:
            # Расширяем существующее расширение padding
            _, start, total_len = extensions[existing_pad_idx]
            old_pad_data_len = total_len - 4
            new_pad_data_len = old_pad_data_len + needed_bytes

            new_ext_bytes = bytearray()
            for idx, (ext_type, s, t_len) in enumerate(extensions):
                if idx == existing_pad_idx:
                    new_ext_bytes.extend(
                        struct.pack("!HH", TLS_PADDING_EXTENSION_TYPE, new_pad_data_len)
                        + (b"\x00" * new_pad_data_len)
                    )
                else:
                    new_ext_bytes.extend(data[s:s + t_len])

            added_len = needed_bytes
        else:
            # Добавляем новое расширение padding в конец блока расширений
            pad_data_len = max(1, needed_bytes - 4)
            new_pad_ext = struct.pack("!HH", TLS_PADDING_EXTENSION_TYPE, pad_data_len) + (b"\x00" * pad_data_len)
            added_len = len(new_pad_ext)

            new_ext_bytes = bytearray()
            for _, s, t_len in extensions:
                new_ext_bytes.extend(data[s:s + t_len])
            new_ext_bytes.extend(new_pad_ext)

        new_ext_len = old_ext_len + added_len

        # Обновление длин TLS Record и Handshake
        old_rec_len = struct.unpack("!H", data[3:5])[0]
        new_rec_len = old_rec_len + added_len

        old_hs_len = int.from_bytes(data[6:9], "big")
        new_hs_len = old_hs_len + added_len

        new_data = (
            data[:3]
            + struct.pack("!H", new_rec_len)
            + data[5:6]
            + new_hs_len.to_bytes(3, "big")
            + data[9:ext_len_pos]
            + struct.pack("!H", new_ext_len)
            + bytes(new_ext_bytes)
            + data[ext_len_pos + 2 + old_ext_len:]
        )
        return new_data
    except Exception as e:
        logger.warning("inject_tls_padding failed: %s", e)
        return data
