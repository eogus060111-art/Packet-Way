/* history.js 테스트 (PLAN 8절: 이력) */
(function (root) {
  'use strict';
  var T = root.PWTest || require('./harness.js');
  var hist = root.PW ? root.PW.history : require('../src/history.js');
  var test = T.test, eq = T.eq, ok = T.ok;

  var RULE = { no: 1, src: 'Any', dst: 'Any', service: 'Any', action: 'allow', purpose: 'x' };

  test('기록한 항목은 time·type·ruleNo·before·after·by 를 가진다', function () {
    var h = hist.create();
    var r = h.record('add', 1, null, RULE, '홍길동');
    ok(r.ok);
    eq(Object.keys(r.entry).sort(), ['after', 'before', 'by', 'ruleNo', 'time', 'type']);
    eq(r.entry.before, null);
    eq(r.entry.after, RULE);
    eq(r.entry.by, '홍길동');
  });

  test('time 은 ISO8601 형식', function () {
    var h = hist.create();
    var t = h.record('add', 1, null, RULE, 'a').entry.time;
    ok(/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(\.\d+)?Z$/.test(t), t);
    ok(!isNaN(Date.parse(t)));
  });

  test('시계를 주입할 수 있다', function () {
    var h = hist.create([], function () { return '2026-01-02T03:04:05.000Z'; });
    eq(h.record('add', 1, null, RULE, 'a').entry.time, '2026-01-02T03:04:05.000Z');
  });

  test('변경자가 비어 있으면 기록하지 않는다', function () {
    var h = hist.create();
    [undefined, null, '', '   ', 5].forEach(function (by) {
      var r = h.record('add', 1, null, RULE, by);
      ok(!r.ok);
      eq(r.error, '변경자를 입력하세요');
    });
    eq(h.size(), 0);
  });

  test('알 수 없는 변경 종류는 기록하지 않는다', function () {
    var h = hist.create();
    ok(!h.record('rename', 1, null, RULE, 'a').ok);
    eq(h.size(), 0);
  });

  test('all 은 오래된 순, recent 는 최신 순', function () {
    var h = hist.create();
    h.record('add', 1, null, RULE, 'a');
    h.record('delete', 1, RULE, null, 'b');
    eq(h.all().map(function (e) { return e.by; }), ['a', 'b']);
    eq(h.recent().map(function (e) { return e.by; }), ['b', 'a']);
  });

  test('이력은 추가만 가능: 돌려받은 항목을 바꿔도 원본은 그대로', function () {
    var h = hist.create();
    h.record('add', 1, null, RULE, 'a');
    var got = h.all();
    got[0].by = '변조';
    got[0].after.src = '변조';
    got.pop();
    eq(h.all()[0].by, 'a');
    eq(h.all()[0].after.src, 'Any');
    eq(h.size(), 1);
  });

  test('기록 이후 원본 규칙을 바꿔도 이력은 그대로(깊은 복사)', function () {
    var h = hist.create();
    var rule = JSON.parse(JSON.stringify(RULE));
    h.record('add', 1, null, rule, 'a');
    rule.src = '변조';
    eq(h.all()[0].after.src, 'Any');
  });

  test('저장된 항목으로 복원할 수 있다', function () {
    var h = hist.create();
    h.record('add', 1, null, RULE, 'a');
    var h2 = hist.create(h.all());
    eq(h2.all(), h.all());
    h2.record('delete', 1, RULE, null, 'b');
    eq(h.size(), 1);
    eq(h2.size(), 2);
  });
})(typeof globalThis !== 'undefined' ? globalThis : this);
