// Widget tests for the account deletion confirmation: the Delete button stays
// disabled until the user types the confirmation text. The dialog needs no
// native SDK library.

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';

import 'package:nexus_client/src/views/settings_view.dart';

Future<List<bool?>> _openDialog(WidgetTester tester) async {
  final results = <bool?>[];
  await tester.pumpWidget(MaterialApp(
    home: Builder(
      builder: (context) => TextButton(
        onPressed: () async => results.add(await confirmAccountDeletion(context)),
        child: const Text('open'),
      ),
    ),
  ));
  await tester.tap(find.text('open'));
  await tester.pumpAndSettle();
  return results;
}

ElevatedButton _deleteButton(WidgetTester tester) => tester.widget<ElevatedButton>(
    find.widgetWithText(ElevatedButton, 'Delete Account'));

void main() {
  testWidgets('Delete stays disabled until the confirmation text is typed', (tester) async {
    final results = await _openDialog(tester);
    expect(_deleteButton(tester).onPressed, isNull);

    await tester.enterText(find.byKey(const Key('delete-account-confirmation')), 'delete');
    await tester.pump();
    expect(_deleteButton(tester).onPressed, isNull, reason: 'the text is case-sensitive');

    await tester.enterText(
        find.byKey(const Key('delete-account-confirmation')), kDeleteAccountConfirmation);
    await tester.pump();
    expect(_deleteButton(tester).onPressed, isNotNull);

    await tester.tap(find.widgetWithText(ElevatedButton, 'Delete Account'));
    await tester.pumpAndSettle();
    expect(results, [true]);
  });

  testWidgets('Cancel never confirms', (tester) async {
    final results = await _openDialog(tester);
    await tester.enterText(
        find.byKey(const Key('delete-account-confirmation')), kDeleteAccountConfirmation);
    await tester.pump();
    await tester.tap(find.text('Cancel'));
    await tester.pumpAndSettle();
    expect(results, [false]);
  });
}
