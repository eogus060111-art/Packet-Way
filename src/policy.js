/* policy.js — 정책표 편집(추가·수정·삭제·이동)과 변경 이력 연동 (SPEC 2-5, PLAN 5절)
 *
 * 규칙을 바꾸는 유일한 경로다. 모든 변경은 검증 → 반영 → 이력 기록 순으로 처리하고,
 * 검증에 실패하면 정책표와 이력은 그대로다. 규칙 번호는 변경 뒤 1부터 연속으로 다시 매긴다.
 *
 * 반환: { ok:true, ... } 또는 { ok:false, errors:[{ field, message }] }
 * 이력 ruleNo: add=새 번호, edit=해당 번호, delete=삭제된 규칙의 번호, move=이동 전 번호
 *   (move 의 before.no / after.no 에 이동 전·후 번호가 모두 남는다) */
(function (root) {
  'use strict';

  var topo = (root.PW && root.PW.topology) || require('./topology.js');
  var validator = (root.PW && root.PW.validator) || require('./validator.js');
  var historyMod = (root.PW && root.PW.history) || require('./history.js');

  var FIELDS = ['src', 'dst', 'service', 'action', 'purpose'];
  var ERR_ACTION = '동작 오류';
  var ERR_NO_RULE = '규칙 번호 오류';
  var ERR_POSITION = '위치 오류';

  function clone(v) { return JSON.parse(JSON.stringify(v)); }
  function fail(field, message) { return { ok: false, errors: [{ field: field, message: message }] }; }

  function normalize(src) {
    var r = {};
    FIELDS.forEach(function (f) {
      var v = src[f];
      if (v === undefined || v === null) v = '';
      r[f] = typeof v === 'string' && f !== 'purpose' ? v.trim() : v;
    });
    return r;
  }

  // 규칙 내용(번호 제외) 검사: 입력 검증(SPEC 2-7) + 동작 값
  function checkContent(content) {
    var errors = validator.validateRule(content).errors.slice();
    if (content.action !== 'allow' && content.action !== 'deny') {
      errors.push({ field: 'action', message: ERR_ACTION });
    }
    return errors;
  }

  function create(opts) {
    opts = opts || {};
    var rules = (opts.rules ? opts.rules : topo.defaultPolicy()).map(clone)
      .sort(function (a, b) { return a.no - b.no; });
    var history = opts.history || historyMod.create(opts.entries, opts.now);

    function renumber() { rules.forEach(function (r, i) { r.no = i + 1; }); }
    function changed() { if (opts.onChange) opts.onChange(api.state()); }
    function indexOfNo(no) {
      for (var i = 0; i < rules.length; i++) if (rules[i].no === no) return i;
      return -1;
    }
    function byError(by) {
      return historyMod.validBy(by) ? null : fail('by', historyMod.ERR_BY);
    }

    var api = {
      history: history,

      rules: function () { return rules.map(clone); },

      state: function () { return { rules: api.rules(), history: history.all() }; },

      // 규칙 추가. at(1..n+1)을 생략하면 맨 아래에 붙는다.
      add: function (rule, by, at) {
        var e = byError(by);
        if (e) return e;
        var content = normalize(rule || {});
        var errors = checkContent(content);
        if (errors.length) return { ok: false, errors: errors };
        var pos = at === undefined ? rules.length + 1 : at;
        if (!Number.isInteger(pos) || pos < 1 || pos > rules.length + 1) return fail('position', ERR_POSITION);

        var newRule = { no: pos, src: content.src, dst: content.dst, service: content.service,
          action: content.action, purpose: content.purpose };
        rules.splice(pos - 1, 0, newRule);
        renumber();
        history.record('add', pos, null, rules[pos - 1], by);
        changed();
        return { ok: true, rule: clone(rules[pos - 1]) };
      },

      // 규칙 수정. changes 에는 src/dst/service/action/purpose 만 반영한다. 바뀐 게 없으면 기록하지 않는다.
      edit: function (no, changes, by) {
        var e = byError(by);
        if (e) return e;
        var idx = indexOfNo(no);
        if (idx === -1) return fail('no', ERR_NO_RULE);

        var before = clone(rules[idx]);
        var merged = {};
        FIELDS.forEach(function (f) { merged[f] = before[f]; });
        FIELDS.forEach(function (f) { if (changes && changes[f] !== undefined) merged[f] = changes[f]; });
        var content = normalize(merged);
        var errors = checkContent(content);
        if (errors.length) return { ok: false, errors: errors };

        var after = { no: before.no, src: content.src, dst: content.dst, service: content.service,
          action: content.action, purpose: content.purpose };
        if (JSON.stringify(after) === JSON.stringify(before)) return { ok: true, changed: false, rule: before };

        rules[idx] = after;
        history.record('edit', no, before, after, by);
        changed();
        return { ok: true, changed: true, rule: clone(after) };
      },

      // 규칙 삭제. 아래 규칙 번호가 하나씩 당겨진다.
      remove: function (no, by) {
        var e = byError(by);
        if (e) return e;
        var idx = indexOfNo(no);
        if (idx === -1) return fail('no', ERR_NO_RULE);

        var removed = rules.splice(idx, 1)[0];
        renumber();
        history.record('delete', no, removed, null, by);
        changed();
        return { ok: true, rule: clone(removed) };
      },

      // 규칙 이동: no 번 규칙을 newNo 번 자리로 옮긴다(사이 규칙은 한 칸씩 밀린다).
      move: function (no, newNo, by) {
        var e = byError(by);
        if (e) return e;
        var idx = indexOfNo(no);
        if (idx === -1) return fail('no', ERR_NO_RULE);
        if (!Number.isInteger(newNo) || newNo < 1 || newNo > rules.length) return fail('position', ERR_POSITION);
        if (newNo === no) return { ok: true, changed: false, rule: clone(rules[idx]) };

        var before = clone(rules[idx]);
        var moved = rules.splice(idx, 1)[0];
        rules.splice(newNo - 1, 0, moved);
        renumber();
        history.record('move', no, before, rules[newNo - 1], by);
        changed();
        return { ok: true, changed: true, rule: clone(rules[newNo - 1]) };
      }
    };

    return api;
  }

  var api = { create: create, ERR_ACTION: ERR_ACTION, ERR_NO_RULE: ERR_NO_RULE, ERR_POSITION: ERR_POSITION };

  root.PW = root.PW || {};
  root.PW.policy = api;
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
})(typeof globalThis !== 'undefined' ? globalThis : this);
