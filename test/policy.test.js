/* policy.js 테스트 (PLAN 8절: add/edit/delete/move 각 1건 기록, edit 의 before/after 는 규칙 전체,
 * 검증 실패 시 이력 없음) */
(function (root) {
  'use strict';
  var T = root.PWTest || require('./harness.js');
  var policyMod = root.PW ? root.PW.policy : require('../src/policy.js');
  var topo = root.PW ? root.PW.topology : require('../src/topology.js');
  var analyzer = root.PW ? root.PW.analyzer : require('../src/analyzer.js');
  var engine = root.PW ? root.PW.engine : require('../src/engine.js');
  var test = T.test, eq = T.eq, ok = T.ok;

  function make(opts) { return policyMod.create(opts); }
  function nos(p) { return p.rules().map(function (r) { return r.no; }); }
  function srcs(p) { return p.rules().map(function (r) { return r.src; }); }
  var NEW = { src: '내부망', dst: 'DMZ', service: 'TCP 25', action: 'allow', purpose: '메일 점검' };

  test('기본 정책표 5행으로 시작하고 이력은 비어 있다', function () {
    var p = make();
    eq(nos(p), [1, 2, 3, 4, 5]);
    eq(p.history.size(), 0);
  });

  test('rules() 는 복사본: 바꿔도 정책표는 그대로', function () {
    var p = make();
    var r = p.rules();
    r[0].action = 'deny';
    r.pop();
    eq(p.rules()[0].action, 'allow');
    eq(p.rules().length, 5);
  });

  // ---- 추가 ----
  test('add: 맨 아래에 붙고 이력 1건(before=null, after=새 규칙 전체)', function () {
    var p = make();
    var r = p.add(NEW, '관리자');
    ok(r.ok);
    eq(nos(p), [1, 2, 3, 4, 5, 6]);
    var h = p.history.all();
    eq(h.length, 1);
    eq(h[0].type, 'add');
    eq(h[0].ruleNo, 6);
    eq(h[0].before, null);
    eq(h[0].after, { no: 6, src: '내부망', dst: 'DMZ', service: 'TCP 25', action: 'allow', purpose: '메일 점검' });
    eq(h[0].by, '관리자');
  });

  test('add: 원하는 위치에 끼워 넣으면 아래 번호가 밀린다', function () {
    var p = make();
    ok(p.add(NEW, '관리자', 2).ok);
    eq(nos(p), [1, 2, 3, 4, 5, 6]);
    eq(p.rules()[1].service, 'TCP 25');
    eq(p.rules()[2].service, 'TCP 1433,3306', '기존 2번이 3번으로');
    eq(p.history.all()[0].ruleNo, 2);
  });

  test('add: 위치가 범위 밖이면 거부', function () {
    var p = make();
    [0, 7, -1, 1.5].forEach(function (at) {
      var r = p.add(NEW, '관리자', at);
      ok(!r.ok, String(at));
      eq(r.errors[0].message, '위치 오류');
    });
    eq(p.history.size(), 0);
    eq(nos(p), [1, 2, 3, 4, 5]);
  });

  test('add: 알 수 없는 주소·서비스 형식 오류는 거부하고 이력도 없다 (SPEC 2-7)', function () {
    var p = make();
    var r = p.add({ src: '300.1.1.1', dst: 'DMZ', service: 'TCP 99999', action: 'allow' }, '관리자');
    ok(!r.ok);
    eq(r.errors, [{ field: 'src', message: '알 수 없는 주소' }, { field: 'service', message: '서비스 형식 오류' }]);
    eq(p.history.size(), 0);
    eq(nos(p), [1, 2, 3, 4, 5]);
  });

  test('add: 동작 값이 allow/deny 가 아니면 거부', function () {
    var p = make();
    var r = p.add({ src: 'Any', dst: 'Any', service: 'Any', action: 'maybe' }, '관리자');
    ok(!r.ok);
    eq(r.errors, [{ field: 'action', message: '동작 오류' }]);
    eq(p.history.size(), 0);
  });

  test('모든 변경은 변경자가 없으면 거부하고 아무것도 바꾸지 않는다', function () {
    var p = make();
    var before = JSON.stringify(p.state());
    [p.add(NEW, ''), p.edit(1, { purpose: 'x' }, '  '), p.remove(1), p.move(1, 2, null)].forEach(function (r) {
      ok(!r.ok);
      eq(r.errors, [{ field: 'by', message: '변경자를 입력하세요' }]);
    });
    eq(JSON.stringify(p.state()), before);
  });

  // ---- 수정 ----
  test('edit: before 는 변경 전 규칙 전체, after 는 변경 후 규칙 전체 (SPEC 2-5)', function () {
    var p = make();
    var old = p.rules()[3];
    var r = p.edit(4, { service: 'UDP 513,TCP 9200' }, '관리자');
    ok(r.ok && r.changed);
    var h = p.history.all();
    eq(h.length, 1);
    eq(h[0].type, 'edit');
    eq(h[0].ruleNo, 4);
    eq(h[0].before, old);
    eq(h[0].after, { no: 4, src: old.src, dst: old.dst, service: 'UDP 513,TCP 9200', action: 'allow', purpose: old.purpose });
    eq(p.rules()[3].service, 'UDP 513,TCP 9200');
  });

  test('edit: 바뀐 게 없으면 이력을 남기지 않는다', function () {
    var p = make();
    var r = p.edit(1, { service: 'TCP 80,443' }, '관리자');
    ok(r.ok);
    eq(r.changed, false);
    eq(p.history.size(), 0);
  });

  test('edit: 검증 실패 시 정책표·이력 그대로', function () {
    var p = make();
    var before = JSON.stringify(p.state());
    var r = p.edit(2, { dst: '없는그룹' }, '관리자');
    ok(!r.ok);
    eq(r.errors, [{ field: 'dst', message: '알 수 없는 주소' }]);
    eq(JSON.stringify(p.state()), before);
  });

  test('edit: 없는 규칙 번호는 거부', function () {
    var p = make();
    var r = p.edit(9, { purpose: 'x' }, '관리자');
    ok(!r.ok);
    eq(r.errors[0].message, '규칙 번호 오류');
    eq(p.history.size(), 0);
  });

  test('edit: 번호(no)는 바꿀 수 없다', function () {
    var p = make();
    p.edit(2, { no: 9, purpose: '새 목적' }, '관리자');
    eq(nos(p), [1, 2, 3, 4, 5]);
  });

  // ---- 삭제 ----
  test('delete: 삭제되고 아래 번호가 당겨지며 이력 1건(before=삭제된 규칙, after=null)', function () {
    var p = make();
    var old = p.rules()[1];
    ok(p.remove(2, '관리자').ok);
    eq(nos(p), [1, 2, 3, 4]);
    eq(p.rules()[1].service, 'TCP 22', '기존 3번이 2번으로');
    var h = p.history.all();
    eq(h.length, 1);
    eq([h[0].type, h[0].ruleNo, h[0].after], ['delete', 2, null]);
    eq(h[0].before, old);
  });

  test('delete: 없는 번호는 거부', function () {
    var p = make();
    ok(!p.remove(0, '관리자').ok);
    ok(!p.remove(6, '관리자').ok);
    eq(p.history.size(), 0);
  });

  // ---- 이동 ----
  test('move: 위로 이동하면 사이 규칙이 한 칸씩 밀리고 이력 1건', function () {
    var p = make();
    var old = p.rules()[3]; // 4번(로그 수집)
    ok(p.move(4, 2, '관리자').ok);
    eq(nos(p), [1, 2, 3, 4, 5]);
    eq(p.rules()[1].service, 'UDP 514,TCP 9200');
    eq(p.rules()[2].service, 'TCP 1433,3306', '기존 2번이 3번으로');
    var h = p.history.all();
    eq(h.length, 1);
    eq([h[0].type, h[0].ruleNo], ['move', 4]);
    eq(h[0].before, old);
    eq(h[0].after.no, 2);
    eq(h[0].after.service, old.service);
  });

  test('move: 아래로 이동', function () {
    var p = make();
    ok(p.move(1, 3, '관리자').ok);
    eq(p.rules()[2].service, 'TCP 80,443');
    eq(p.rules()[0].service, 'TCP 1433,3306');
    eq(nos(p), [1, 2, 3, 4, 5]);
  });

  test('move: 같은 자리는 이력을 남기지 않는다', function () {
    var p = make();
    var r = p.move(3, 3, '관리자');
    ok(r.ok);
    eq(r.changed, false);
    eq(p.history.size(), 0);
  });

  test('move: 범위 밖 위치·없는 번호는 거부', function () {
    var p = make();
    [0, 6, 2.5].forEach(function (n) { ok(!p.move(1, n, '관리자').ok, String(n)); });
    ok(!p.move(9, 1, '관리자').ok);
    eq(p.history.size(), 0);
    eq(nos(p), [1, 2, 3, 4, 5]);
  });

  // ---- 이력 전체 ----
  test('변경마다 이력이 시간 순으로 한 건씩 쌓인다', function () {
    var p = make();
    p.add(NEW, 'a');
    p.edit(6, { purpose: '수정' }, 'b');
    p.move(6, 1, 'c');
    p.remove(1, 'd');
    eq(p.history.all().map(function (e) { return e.type; }), ['add', 'edit', 'move', 'delete']);
    eq(p.history.all().map(function (e) { return e.by; }), ['a', 'b', 'c', 'd']);
    eq(p.history.recent()[0].type, 'delete');
  });

  test('onChange 는 성공한 변경에만 최신 상태와 함께 호출된다', function () {
    var calls = [];
    var p = make({ onChange: function (s) { calls.push(s); } });
    p.add({ src: 'x', dst: 'Any', service: 'Any', action: 'allow' }, 'a'); // 실패
    p.edit(1, { purpose: 'y' }, 'a');                                   // 성공
    eq(calls.length, 1);
    eq(calls[0].history.length, 1);
    eq(calls[0].rules[0].purpose, 'y');
  });

  test('저장한 상태로 복원할 수 있다', function () {
    var p = make();
    p.add(NEW, 'a');
    p.remove(2, 'b');
    var s = p.state();
    var q = make({ rules: s.rules, entries: s.history });
    eq(q.state(), s);
    q.edit(1, { purpose: '이어서' }, 'c');
    eq(q.history.size(), 3);
    eq(p.history.size(), 2);
  });

  // ---- 판정·점검과 연결 ----
  test('연결: 5번(기본 거부)을 삭제하면 점검이 경고하고 판정은 암묵적 차단', function () {
    var p = make();
    ok(p.remove(5, '관리자').ok);
    eq(analyzer.analyze(p.rules()).warnings.map(function (w) { return w.type; }), ['default-deny']);
    var r = engine.judge(p.rules(), { srcIp: '10.20.1.20', dstIp: '203.0.113.10', proto: 'TCP', port: 443 });
    eq([r.action, r.matched], ['deny', null]);
  });

  test('연결: 이동한 규칙 순서가 판정 결과를 바꾼다', function () {
    var p = make();
    p.add({ src: 'Any', dst: 'DMZ 웹서버', service: 'TCP 80', action: 'deny', purpose: '차단' }, 'a', 1);
    var pkt = { srcIp: '203.0.113.10', dstIp: '172.16.10.10', proto: 'TCP', port: 80 };
    eq(engine.judge(p.rules(), pkt).action, 'deny');
    p.move(1, 2, 'a');
    eq(engine.judge(p.rules(), pkt).action, 'allow');
  });
})(typeof globalThis !== 'undefined' ? globalThis : this);
