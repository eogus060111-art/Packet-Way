/* validator.js 테스트 (PLAN 8절: 입력 검증) */
(function (root) {
  'use strict';
  var T = root.PWTest || require('./harness.js');
  var val = root.PW ? root.PW.validator : require('../src/validator.js');
  var topo = root.PW ? root.PW.topology : require('../src/topology.js');
  var test = T.test, eq = T.eq, ok = T.ok;

  function rule(src, dst, service) {
    return { no: 1, src: src, dst: dst, service: service, action: 'allow', purpose: '' };
  }

  test('올바른 규칙은 통과', function () {
    ok(val.validateRule(rule('외부망', 'DMZ 웹서버', 'TCP 80,443')).ok);
    ok(val.validateRule(rule('Any', 'Any', 'Any')).ok);
    ok(val.validateRule(rule('10.20.1.20', '203.0.113.10', 'TCP 443')).ok);
  });

  test('잘못된 IP → 알 수 없는 주소 (SPEC 2-7)', function () {
    var r = val.validateRule(rule('300.1.1.1', 'DMZ', 'TCP 80'));
    ok(!r.ok);
    eq(r.errors, [{ field: 'src', message: '알 수 없는 주소' }]);
  });

  test('없는 그룹 이름은 목적지 오류', function () {
    var r = val.validateRule(rule('DMZ', '없는그룹', 'TCP 80'));
    eq(r.errors, [{ field: 'dst', message: '알 수 없는 주소' }]);
  });

  test('잘못된 서비스 → 서비스 형식 오류 (SPEC 2-7)', function () {
    ['TCP', 'TCP 99999'].forEach(function (s) {
      var r = val.validateRule(rule('DMZ', 'DMZ', s));
      ok(!r.ok);
      eq(r.errors, [{ field: 'service', message: '서비스 형식 오류' }]);
    });
  });

  test('오류가 여럿이면 모두 보고', function () {
    var r = val.validateRule(rule('x', 'y', 'z'));
    eq(r.errors.map(function (e) { return e.field; }), ['src', 'dst', 'service']);
  });

  test('기본 정책표 5행은 검증을 통과한다', function () {
    ok(val.validatePolicy(topo.defaultPolicy()).ok);
  });

  test('validatePolicy 는 오류에 규칙 번호를 붙인다', function () {
    var p = topo.defaultPolicy();
    p[2].service = 'TCP 99999';
    var r = val.validatePolicy(p);
    ok(!r.ok);
    eq(r.errors, [{ ruleNo: 3, field: 'service', message: '서비스 형식 오류' }]);
  });
})(typeof globalThis !== 'undefined' ? globalThis : this);
