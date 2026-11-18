/* engine.js 테스트 (PLAN 8절: T2, first-match, 암묵적 차단, 구간별 허용·역방향 차단) */
(function (root) {
  'use strict';
  var T = root.PWTest || require('./harness.js');
  var engine = root.PW ? root.PW.engine : require('../src/engine.js');
  var topo = root.PW ? root.PW.topology : require('../src/topology.js');
  var test = T.test, eq = T.eq, ok = T.ok;

  function pkt(srcIp, dstIp, proto, port) {
    return { srcIp: srcIp, dstIp: dstIp, proto: proto, port: port };
  }
  function judge(packet, rules) { return engine.judge(rules || topo.defaultPolicy(), packet); }
  function verdict(packet, rules) {
    var r = judge(packet, rules);
    return [r.action, r.matched];
  }

  // ---- SPEC 3 함정 2 (T2) ----
  test('T2: 개발 서버(10.20.1.20) → 인터넷(203.0.113.10) TCP 443 은 5번 규칙에 걸려 차단', function () {
    var r = judge(pkt('10.20.1.20', '203.0.113.10', 'TCP', 443));
    eq(r.action, 'deny');
    eq(r.matched, 5);
    eq(r.srcZone, '개발·운영 서버망');
    eq(r.dstZone, '인터넷');
  });

  // ---- 구간별 허용 (SPEC 1-2) ----
  test('1번: 외부 → 웹서버 TCP 80/443 허용', function () {
    eq(verdict(pkt('203.0.113.10', '172.16.10.10', 'TCP', 80)), ['allow', 1]);
    eq(verdict(pkt('203.0.113.10', '172.16.10.10', 'TCP', 443)), ['allow', 1]);
  });

  test('1번 범위 밖(다른 포트, 다른 서버, UDP)은 5번 차단', function () {
    eq(verdict(pkt('203.0.113.10', '172.16.10.10', 'TCP', 8080)), ['deny', 5]);
    eq(verdict(pkt('203.0.113.10', '172.16.10.20', 'TCP', 80)), ['deny', 5]);
    eq(verdict(pkt('203.0.113.10', '172.16.10.10', 'UDP', 80)), ['deny', 5]);
  });

  test('2번: 웹서버 → DB TCP 1433/3306 허용, 다른 DMZ 호스트는 차단', function () {
    eq(verdict(pkt('172.16.10.10', '192.168.10.30', 'TCP', 3306)), ['allow', 2]);
    eq(verdict(pkt('172.16.10.10', '192.168.10.30', 'TCP', 1433)), ['allow', 2]);
    eq(verdict(pkt('172.16.10.20', '192.168.10.30', 'TCP', 3306)), ['deny', 5]);
  });

  test('3번: 관리자 PC → 개발·운영 서버 SSH 허용, 업무 PC 는 차단', function () {
    eq(verdict(pkt('192.168.10.5', '10.20.1.20', 'TCP', 22)), ['allow', 3]);
    eq(verdict(pkt('192.168.10.5', '10.20.1.10', 'TCP', 22)), ['allow', 3]);
    eq(verdict(pkt('192.168.10.100', '10.20.1.20', 'TCP', 22)), ['deny', 5]);
  });

  test('4번: 내부 장비·DMZ → SIEM 로그 수집(UDP 514, TCP 9200) 허용', function () {
    eq(verdict(pkt('192.168.10.30', '192.168.10.50', 'UDP', 514)), ['allow', 4]);
    eq(verdict(pkt('192.168.10.30', '192.168.10.50', 'TCP', 9200)), ['allow', 4]);
    eq(verdict(pkt('172.16.10.10', '192.168.10.50', 'UDP', 514)), ['allow', 4]);
    eq(verdict(pkt('192.168.10.30', '192.168.10.50', 'TCP', 514)), ['deny', 5]);
    eq(verdict(pkt('192.168.10.30', '192.168.10.50', 'UDP', 513)), ['deny', 5]);
  });

  test('역방향 트래픽은 5번으로 차단', function () {
    eq(verdict(pkt('172.16.10.10', '203.0.113.10', 'TCP', 443)), ['deny', 5]);
    eq(verdict(pkt('192.168.10.30', '172.16.10.10', 'TCP', 3306)), ['deny', 5]);
    eq(verdict(pkt('10.20.1.20', '192.168.10.5', 'TCP', 22)), ['deny', 5]);
  });

  // ---- first-match (SPEC 2-1) ----
  var allowAll = { no: 1, src: 'Any', dst: 'Any', service: 'Any', action: 'allow', purpose: '' };
  var denyWeb = { no: 2, src: 'Any', dst: 'DMZ 웹서버', service: 'TCP 80', action: 'deny', purpose: '' };

  test('first-match: 허용이 위, 같은 범위 차단이 아래면 결과는 허용', function () {
    var rules = [
      { no: 1, src: '외부망', dst: 'DMZ 웹서버', service: 'TCP 80', action: 'allow', purpose: '' },
      { no: 2, src: '외부망', dst: 'DMZ 웹서버', service: 'TCP 80', action: 'deny', purpose: '' }
    ];
    eq(verdict(pkt('203.0.113.10', '172.16.10.10', 'TCP', 80), rules), ['allow', 1]);
  });

  test('first-match: 순서를 바꾸면 결과가 바뀐다', function () {
    var rules = [
      { no: 1, src: '외부망', dst: 'DMZ 웹서버', service: 'TCP 80', action: 'deny', purpose: '' },
      { no: 2, src: '외부망', dst: 'DMZ 웹서버', service: 'TCP 80', action: 'allow', purpose: '' }
    ];
    eq(verdict(pkt('203.0.113.10', '172.16.10.10', 'TCP', 80), rules), ['deny', 1]);
  });

  test('first-match: 1번이 Any→Any 허용이면 아래 차단 규칙은 적용되지 않는다', function () {
    eq(verdict(pkt('203.0.113.10', '172.16.10.10', 'TCP', 80), [allowAll, denyWeb]), ['allow', 1]);
    eq(verdict(pkt('10.20.1.20', '203.0.113.10', 'TCP', 443), [allowAll, denyWeb]), ['allow', 1]);
  });

  test('first-match: 첫 일치에서 멈추고 아래 규칙은 trace 에 없다', function () {
    var r = judge(pkt('192.168.10.30', '192.168.10.50', 'UDP', 514));
    eq(r.matched, 4);
    eq(r.trace.map(function (t) { return t.no; }), [1, 2, 3, 4]);
    eq(r.trace.map(function (t) { return t.matched; }), [false, false, false, true]);
  });

  test('규칙 번호 순서로 평가한다(배열 순서가 달라도)', function () {
    var rules = topo.defaultPolicy().reverse();
    eq(verdict(pkt('203.0.113.10', '172.16.10.10', 'TCP', 443), rules), ['allow', 1]);
  });

  test('judge 는 입력 규칙 배열의 순서를 바꾸지 않는다', function () {
    var rules = topo.defaultPolicy().reverse();
    judge(pkt('203.0.113.10', '172.16.10.10', 'TCP', 443), rules);
    eq(rules.map(function (r) { return r.no; }), [5, 4, 3, 2, 1]);
  });

  // ---- trace 의 불일치 사유 ----
  test('trace 에 어느 항목이 달랐는지 담긴다', function () {
    var r = judge(pkt('203.0.113.10', '172.16.10.10', 'TCP', 22));
    eq(r.trace[0], { no: 1, action: 'allow', matched: false, mismatch: ['서비스'] });
    eq(r.trace[1].mismatch, ['출발지', '목적지', '서비스']);
    eq(r.trace[4], { no: 5, action: 'deny', matched: true, mismatch: [] });
  });

  // ---- 암묵적 차단 (SPEC 2-1) ----
  test('일치 규칙이 없으면 암묵적 차단 + 경고', function () {
    var rules = topo.defaultPolicy().slice(0, 4); // 5번(기본 거부) 삭제
    var r = judge(pkt('8.8.8.8', '172.16.10.10', 'TCP', 22), rules);
    eq(r.ok, true);
    eq(r.action, 'deny');
    eq(r.matched, null);
    eq(r.warnings, ['일치 규칙 없음 — 기본 거부 규칙 필요']);
    eq(r.trace.length, 4);
  });

  test('빈 정책표도 암묵적 차단', function () {
    var r = judge(pkt('8.8.8.8', '172.16.10.10', 'TCP', 22), []);
    eq([r.action, r.matched, r.warnings.length], ['deny', null, 1]);
  });

  test('명시적 규칙에 걸린 판정에는 경고가 없다', function () {
    eq(judge(pkt('203.0.113.10', '172.16.10.10', 'TCP', 80)).warnings, []);
    eq(judge(pkt('10.20.1.20', '203.0.113.10', 'TCP', 443)).warnings, []);
  });

  // ---- 입력 오류 ----
  test('패킷 입력 오류는 SPEC 2-7 문구로 거부', function () {
    var r = judge(pkt('300.1.1.1', '172.16.10.10', 'TCP', 80));
    eq(r.ok, false);
    eq(r.errors, [{ field: 'srcIp', message: '알 수 없는 주소' }]);
    eq(judge(pkt('10.0.0.1', 'abc', 'TCP', 80)).errors, [{ field: 'dstIp', message: '알 수 없는 주소' }]);
    eq(judge(pkt('10.0.0.1', '10.0.0.2', 'ICMP', 80)).errors, [{ field: 'proto', message: '서비스 형식 오류' }]);
    eq(judge(pkt('10.0.0.1', '10.0.0.2', 'TCP', 0)).errors, [{ field: 'port', message: '서비스 형식 오류' }]);
    eq(judge(pkt('10.0.0.1', '10.0.0.2', 'TCP', 70000)).errors, [{ field: 'port', message: '서비스 형식 오류' }]);
    eq(judge(pkt('10.0.0.1', '10.0.0.2', 'TCP', '80')).errors, [{ field: 'port', message: '서비스 형식 오류' }]);
    eq(judge(null).ok, false);
  });

  test('프로토콜은 소문자도 허용', function () {
    eq(verdict(pkt('203.0.113.10', '172.16.10.10', 'tcp', 80)), ['allow', 1]);
  });

  test('해석할 수 없는 규칙은 일치하지 않는 것으로 건너뛴다', function () {
    var rules = [
      { no: 1, src: '없는그룹', dst: 'Any', service: 'Any', action: 'allow', purpose: '' },
      { no: 2, src: 'Any', dst: 'Any', service: 'Any', action: 'deny', purpose: '' }
    ];
    eq(verdict(pkt('10.0.0.1', '10.0.0.2', 'TCP', 80), rules), ['deny', 2]);
  });
})(typeof globalThis !== 'undefined' ? globalThis : this);
