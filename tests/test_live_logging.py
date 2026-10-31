"""Журнал ограничивает память и связывает записи одного соединения."""
import io
import logging
import unittest
from unittest.mock import Mock, patch

from flowguard import logger as log_module


class LiveLogTests(unittest.TestCase):
    def test_wide_menu_keeps_tools_and_exit_when_art_is_short(self):
        from flowguard.main import FloweryApp
        app = object.__new__(FloweryApp)
        app.config = Mock()
        app._is_active = False
        app.active_profile_name = 'Тест'
        app.proxy_server = None
        output = io.StringIO()
        with patch('flowguard.main.FLOWEY_ART', ['flower']), \
                patch('flowguard.main.shutil.get_terminal_size', return_value=Mock(columns=120)), \
                patch('flowguard.main.os.system'), patch('sys.stdout', output):
            app.render_menu()
        for text in ('Живой журнал', 'Выход'):
            self.assertIn(text, output.getvalue())
        self.assertNotIn('Проверить сертификат', output.getvalue())

    def test_bounded_history_and_control_characters(self):
        handler = log_module.LiveLogHandler(capacity=2)
        for text in ('old', 'two', '\x1b[31mthree\x00'):
            handler.handle(logging.LogRecord('Flowery.Test', 20, '', 0, text, (), None))
        self.assertEqual(handler.snapshot(), ['two', 'three'])

    def test_view_unsubscribes_without_stopping_service(self):
        logger = logging.getLogger('Flowery')
        before = list(logger.handlers)
        output = io.StringIO()
        log_module.show_live_log(output=output, stop_requested=lambda: True)
        self.assertEqual(logger.handlers, before)
        self.assertIn('журнал', output.getvalue().lower())

    def test_connection_id_is_scoped_and_exceptions_propagate(self):
        ids = []
        @log_module.trace_connection
        def request():
            ids.append(log_module.current_connection_id())
            raise ValueError('test')
        for _ in range(2):
            with self.assertRaises(ValueError):
                request()
            self.assertEqual(log_module.current_connection_id(), '-')
        self.assertNotEqual(ids[0], ids[1])
        self.assertNotIn('-', ids)
