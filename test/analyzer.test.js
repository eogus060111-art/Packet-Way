/* analyzer.js 테스트 (PLAN 8절: T1, T3, 기본 거부, 중복) */
(function (root) {
  'use strict';
  var T = root.PWTest || require('./harness.js');
  var analyzer = root.PW ? root.PW.analyzer : require('../src/analyzer.js');
  var topo = root.PW ? root.PW.topology : require('../src/topology.js');
  var test = T.test, eq = T.eq, ok = T.ok;

  function rule(no, src, dst, service, action, purpose) {
    return { no: no, src: src, dst: dst, service: service, action: action, purpose: purpose || '' };
  }
  function messages(rules) {
    return analyzer.analyze(rules).warnings.map(function (w) { return w.message; });
  }
  function types(rules) {
    return analyzer.analyze(rules).warnings.map(function (w) { return w.type + ':' + w.ruleNo; });
  }

  test('기본 정책표 5행은 경고가 없다', function () {
    eq(messages(topo.defaultPolicy()), []);
  });

  // ---- SPEC 3 함정 1 (T1) ----
  test('T1: 1번이 Any→Any 허용이면 아래 차단 규칙은 모두 섀도잉', function () {
    var rules = [
      rule(1, 'Any', 'Any', 'Any', 'allow'),
      rule(2, 'Any', 'DMZ 웹서버', 'TCP 80', 'deny'),
      rule(3, 'DMZ', '내부망', 'TCP 3306', 'deny'),
      rule(4, 'Any', 'Any', 'Any', 'deny', '기본 거부')
    ];
    var w = analyzer.analyze(rules).warnings.filter(function (x) { return x.type === 'shadowing'; });
    eq(w.map(function (x) { return x.ruleNo; }), [2, 3, 4]);
    ok(w.every(function (x) { return x.relatedNo === 1; }), '모두 1번 때문');
    eq(w[0].message, '규칙 2 는 규칙 1 에 가려져 절대 적용되지 않습니다(섀도잉)');
  });

  test('T1: 기본 정책표의 1번만 Any→Any 허용으로 바꾸면 5번(기본 거부)이 섀도잉', function () {
    var rules = topo.defaultPolicy();
    rules[0] = rule(1, 'Any', 'Any', 'Any', 'allow');
    var m = messages(rules);
    ok(m.indexOf('규칙 5 는 규칙 1 에 가려져 절대 적용되지 않습니다(섀도잉)') !== -1);
  });

  test('섀도잉: 같은 동작이면 섀도잉이 아니라 중복', function () {
    var rules = [
      rule(1, 'Any', 'Any', 'Any', 'allow'),
      rule(2, '외부망', 'DMZ 웹서버', 'TCP 80,443', 'allow'),
      rule(3, 'Any', 'Any', 'Any', 'deny')
    ];
    eq(types(rules), ['redundancy:2', 'shadowing:3']);
    eq(messages(rules)[0], '규칙 2 는 규칙 1 와 중복입니다(같은 트래픽·같은 동작)');
  });

  test('섀도잉: 구역이 단일 IP 규칙을 가린다', function () {
    var rules = [
      rule(1, '외부망', 'DMZ', 'TCP 80,443', 'allow'),
      rule(2, '203.0.113.10', '172.16.10.10', 'TCP 443', 'deny'),
      rule(3, 'Any', 'Any', 'Any', 'deny')
    ];
    eq(types(rules), ['shadowing:2']);
  });

  test('일부만 겹치면 섀도잉이 아니다 (서비스·주소가 완전히 덮이지 않음)', function () {
    eq(types([
      rule(1, 'Any', 'DMZ 웹서버', 'TCP 80', 'allow'),
      rule(2, 'Any', 'DMZ 웹서버', 'TCP 80,443', 'deny'),
      rule(3, 'Any', 'Any', 'Any', 'deny')
    ]), []);
    eq(types([
      rule(1, '내부망 DB 서버', 'Any', 'Any', 'allow'),
      rule(2, '내부망', 'Any', 'Any', 'deny'),
      rule(3, 'Any', 'Any', 'Any', 'deny')
    ]), []);
  });

  test('가림은 위→아래 방향만: 좁은 위 규칙은 넓은 아래 규칙을 가리지 않는다', function () {
    // 1번(좁은 차단)은 2번(Any 허용)을 가리지 않고, 2번만 3번을 가린다
    eq(types([
      rule(1, '외부망', 'DMZ 웹서버', 'TCP 80', 'deny'),
      rule(2, 'Any', 'Any', 'Any', 'allow'),
      rule(3, 'Any', 'Any', 'Any', 'deny')
    ]), ['shadowing:3']);
  });

  // ---- 중복 (SPEC 2-4) ----
  test('중복: 위 규칙이 아래 규칙을 덮고 동작이 같다', function () {
    var rules = [
      rule(1, '외부망', 'DMZ 웹서버', 'TCP 80,443', 'allow'),
      rule(2, '외부망', 'DMZ 웹서버', 'TCP 80', 'allow'),
      rule(3, 'Any', 'Any', 'Any', 'deny')
    ];
    eq(types(rules), ['redundancy:2']);
  });

  test('중복: 완전히 같은 규칙 두 줄', function () {
    var rules = topo.defaultPolicy();
    rules.splice(1, 0, rule(2, '외부망', 'DMZ 웹서버', 'TCP 80,443', 'allow'));
    rules.forEach(function (r, i) { r.no = i + 1; });
    eq(types(rules), ['redundancy:2']);
  });

  // ---- 기본 거부 (SPEC 2-2) ----
  test('기본 거부: 마지막 규칙이 Any-Any-Any 차단이 아니면 경고', function () {
    var rules = topo.defaultPolicy().slice(0, 4);
    eq(messages(rules), ['마지막 Any-Any 차단(기본 거부) 규칙이 없습니다']);
    eq(analyzer.analyze(rules).warnings[0].ruleNo, null);
  });

  test('기본 거부: 마지막이 Any→Any 허용이거나 서비스가 Any 가 아니면 경고', function () {
    var a = topo.defaultPolicy(); a[4].action = 'allow';
    ok(types(a).indexOf('default-deny:null') !== -1);
    var b = topo.defaultPolicy(); b[4].service = 'TCP 80';
    ok(types(b).indexOf('default-deny:null') !== -1);
    var c = topo.defaultPolicy(); c[4].dst = 'DMZ';
    ok(types(c).indexOf('default-deny:null') !== -1);
  });

  test('기본 거부: 빈 정책표도 경고', function () {
    eq(messages([]), ['마지막 Any-Any 차단(기본 거부) 규칙이 없습니다']);
  });

  test('기본 거부: Any-Any-Any 차단이 중간에 있으면 마지막이 아니므로 경고, 아래 규칙은 섀도잉', function () {
    var rules = [
      rule(1, 'Any', 'Any', 'Any', 'deny'),
      rule(2, '외부망', 'DMZ 웹서버', 'TCP 80', 'allow')
    ];
    eq(types(rules), ['default-deny:null', 'shadowing:2']);
  });

  test('규칙 번호 순서로 점검한다(배열 순서가 달라도)', function () {
    eq(messages(topo.defaultPolicy().reverse()), []);
  });

  // ---- syslog (SPEC 2-6, 함정 3 / T3) ----
  test('T3: syslog 규칙 포트를 UDP 513 으로 넣으면 표준 포트 경고', function () {
    var rules = topo.defaultPolicy();
    rules[3].service = 'UDP 513,TCP 9200';
    eq(messages(rules), ['규칙 4: syslog 표준 포트가 아님 (UDP 513 → 표준 포트는 UDP 514)']);
    eq(analyzer.analyze(rules).warnings[0].type, 'syslog');
  });

  test('T3: UDP 514 면 경고 없음', function () {
    var rules = topo.defaultPolicy();
    rules[3].service = 'UDP 514,TCP 9200';
    eq(messages(rules), []);
  });

  test('syslog: 서비스가 Any 이거나 514 를 포함하는 범위면 경고 없음', function () {
    var rules = topo.defaultPolicy();
    rules[3].service = 'Any';
    eq(messages(rules), []);
    rules[3].service = 'UDP 500-520';
    eq(messages(rules), []);
  });

  test('syslog: 목적지가 SIEM 호스트 IP 인 규칙도 로그 수집 규칙', function () {
    var rules = topo.defaultPolicy();
    rules[3].dst = '192.168.10.50';
    rules[3].service = 'UDP 513';
    eq(types(rules), ['syslog:4']);
  });

  test('syslog: 목적에 syslog / 로그 가 들어 있으면 로그 수집 규칙', function () {
    var a = topo.defaultPolicy();
    a[3].dst = '내부망'; a[3].purpose = 'syslog 수집'; a[3].service = 'UDP 513';
    eq(types(a), ['syslog:4']);
    var b = topo.defaultPolicy();
    b[3].dst = '내부망'; b[3].purpose = '로그 수집'; b[3].service = 'UDP 513';
    eq(types(b), ['syslog:4']);
  });

  test('syslog: 로그 수집 규칙이 아니면 UDP 513 이어도 경고 없음', function () {
    var rules = topo.defaultPolicy();
    rules[3].dst = '내부망'; rules[3].purpose = '기타'; rules[3].service = 'UDP 513';
    eq(types(rules), []);
  });

  test('syslog: UDP 없이 TCP 9200 만 쓰는 로그 규칙은 경고하지 않는다', function () {
    var rules = topo.defaultPolicy();
    rules[3].service = 'TCP 9200';
    eq(messages(rules), []);
  });

  // ---- 기타 ----
  test('형식 오류가 있는 규칙은 점검에서 제외한다', function () {
    var rules = topo.defaultPolicy();
    rules[1].src = '없는그룹';
    eq(messages(rules), []);
  });

  test('analyze 는 입력 규칙을 바꾸지 않는다', function () {
    var rules = topo.defaultPolicy().reverse();
    analyzer.analyze(rules);
    eq(rules.map(function (r) { return r.no; }), [5, 4, 3, 2, 1]);
  });
})(typeof globalThis !== 'undefined' ? globalThis : this);
