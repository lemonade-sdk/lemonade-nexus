import 'package:flutter_test/flutter_test.dart';
import 'package:lemonade_nexus_sdk/lemonade_nexus_sdk.dart';

void main() {
  test('Tier1Progress reads the ln_tier1_progress JSON', () {
    final p = Tier1Progress.fromJson({
      'active': true,
      'epoch': 36,
      'target': 100,
      'pages_done': 2,
      'pages_total': 4,
    });
    expect(p.active, isTrue);
    expect(p.epoch, 36);
    expect(p.target, 100);
    expect(p.pagesDone, 2);
    expect(p.pagesTotal, 4);
  });

  test('Tier1Progress treats missing fields as unknown', () {
    final p = Tier1Progress.fromJson({});
    expect(p.active, isFalse);
    expect(p.pagesTotal, 0);
  });
}
