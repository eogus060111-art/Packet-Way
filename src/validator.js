/* validator.js — 규칙 입력 검증 (SPEC 2-7)
 * 출발지/목적지: Any·구역 이름·주소 그룹 이름·올바른 IPv4 가 아니면 "알 수 없는 주소"
 * 서비스: 형식에 맞지 않으면 "서비스 형식 오류" */
(function (root) {
  'use strict';

  var address = (root.PW && root.PW.address) || require('./address.js');
  var service = (root.PW && root.PW.service) || require('./service.js');

  // 규칙 하나를 검사한다. 반환: { ok, errors:[{ field, message }] }
  function validateRule(rule) {
    var errors = [];
    var s = address.resolve(rule.src);
    if (!s.ok) errors.push({ field: 'src', message: s.error });
    var d = address.resolve(rule.dst);
    if (!d.ok) errors.push({ field: 'dst', message: d.error });
    var v = service.parse(rule.service);
    if (!v.ok) errors.push({ field: 'service', message: v.error });
    return { ok: errors.length === 0, errors: errors };
  }

  // 정책표 전체를 검사한다. 오류마다 ruleNo 를 붙인다.
  function validatePolicy(rules) {
    var errors = [];
    rules.forEach(function (r) {
      validateRule(r).errors.forEach(function (e) {
        errors.push({ ruleNo: r.no, field: e.field, message: e.message });
      });
    });
    return { ok: errors.length === 0, errors: errors };
  }

  var api = { validateRule: validateRule, validatePolicy: validatePolicy };

  root.PW = root.PW || {};
  root.PW.validator = api;
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
})(typeof globalThis !== 'undefined' ? globalThis : this);
