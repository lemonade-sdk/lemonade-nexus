/// Lightweight SSE event parser.
library;

import 'dart:async';
import 'dart:convert';
import 'package:http/http.dart' as http;

class SseEvent {
  final String event; // type between "event: " and "\n", defaults to "message"
  final String data; // accumulated "data: " lines

  const SseEvent({this.event = 'message', required this.data});
}

Stream<SseEvent> parseSseStream(http.ByteStream stream) async* {
  String? currentEvent;
  final currentData = <String>[];

  await for (final line in utf8.decoder.bind(stream).transform(const LineSplitter())) {
    if (line.isEmpty) {
      // End of event — emit it.
      final data = currentData.join('\n');
      if (data.isNotEmpty) {
        yield SseEvent(event: currentEvent ?? 'message', data: data);
      }
      currentData.clear();
      continue;
    }

    if (line.startsWith('event:')) {
      currentEvent = line.substring(6).trim();
    } else if (line.startsWith('data:')) {
      currentData.add(line.substring(5).trim());
    } else if (line.startsWith(':')) {
      // Comment — ignore.
    }
  }

  // Flush remaining data (if stream ends without double newline).
  final data = currentData.join('\n');
  if (data.isNotEmpty) {
    yield SseEvent(event: currentEvent ?? 'message', data: data);
  }
}
