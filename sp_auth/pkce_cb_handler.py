import logging
import urllib.parse
from http.server import BaseHTTPRequestHandler
from queue import Queue

logger = logging.getLogger(__name__)


def make_callback_handler(queue: Queue[str]):
    class CallbackHandler(BaseHTTPRequestHandler):
        def do_GET(self):
            parsed = urllib.parse.urlparse(self.path)
            params = urllib.parse.parse_qs(parsed.query)

            if "code" in params:
                queue.put_nowait(params["code"][0])

                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.end_headers()
                self.wfile.write(
                    b"Authorization successful. You may close this window."
                )
            else:
                self.send_response(400)
                self.end_headers()

        def log_message(self, format: str, *args) -> None:
            logger.debug("%s - %s", self.client_address[0], format % args)

    return CallbackHandler
