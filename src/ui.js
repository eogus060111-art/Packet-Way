/* ui.js — 화면 (PLAN 7절). 판정·점검·편집·이력 로직은 다른 모듈을 호출만 한다.
 * #app 안에 정책표, 토폴로지, 패킷 길찾기, 정책 점검, 변경 이력을 만든다. */
(function (root) {
  'use strict';

  var PW = root.PW;
  var topo = PW.topology;
  var STORAGE_KEY = 'packet-way/v1';
  var BY_KEY = 'packet-way/by';
  var SVGNS = 'http://www.w3.org/2000/svg';

  var FIELD_LABEL = {
    src: '출발지', dst: '목적지', service: '서비스', action: '동작', by: '변경자',
    position: '위치', no: '규칙 번호', srcIp: '출발 IP', dstIp: '도착 IP', proto: '프로토콜', port: '포트'
  };
  var TYPE_LABEL = { add: '추가', edit: '수정', delete: '삭제', move: '이동' };
  var WARN_LABEL = { 'default-deny': '기본 거부', shadowing: '섀도잉', redundancy: '중복', syslog: 'syslog' };

  var PRESETS = [
    { label: '웹 접속 (외부→웹서버 443)', p: { srcIp: '203.0.113.10', dstIp: '172.16.10.10', proto: 'TCP', port: 443 } },
    { label: 'DB 연동 (웹서버→DB 3306)', p: { srcIp: '172.16.10.10', dstIp: '192.168.10.30', proto: 'TCP', port: 3306 } },
    { label: '관리자 SSH (관리자 PC→개발 서버 22)', p: { srcIp: '192.168.10.5', dstIp: '10.20.1.20', proto: 'TCP', port: 22 } },
    { label: '로그 수집 (DB→SIEM UDP 514)', p: { srcIp: '192.168.10.30', dstIp: '192.168.10.50', proto: 'UDP', port: 514 } },
    { label: '함정 2: 개발 서버→인터넷 443', p: { srcIp: '10.20.1.20', dstIp: '203.0.113.10', proto: 'TCP', port: 443 } },
    { label: '역방향 (DB→웹서버 3306)', p: { srcIp: '192.168.10.30', dstIp: '172.16.10.10', proto: 'TCP', port: 3306 } }
  ];

  // ---------- DOM 도우미 ----------
  function append(el, kids) {
    (Array.isArray(kids) ? kids : [kids]).forEach(function (k) {
      if (k === null || k === undefined || k === false) return;
      if (Array.isArray(k)) { append(el, k); return; }
      el.appendChild(typeof k === 'object' ? k : root.document.createTextNode(String(k)));
    });
  }

  function build(el, attrs, kids, svg) {
    var late = null;
    Object.keys(attrs || {}).forEach(function (k) {
      var v = attrs[k];
      if (v === null || v === undefined || v === false) return;
      if (k.indexOf('on') === 0 && typeof v === 'function') el.addEventListener(k.slice(2), v);
      else if (k === 'value') late = v;                       // select 는 option 이 붙은 뒤에 값을 정한다
      else if (k === 'className') { if (svg) el.setAttribute('class', v); else el.className = v; }
      else if (k === 'text') el.textContent = v;
      else if (k === 'disabled' || k === 'checked') el[k] = true;
      else el.setAttribute(k, v === true ? '' : v);
    });
    append(el, kids);
    if (late !== null) el.value = late;
    return el;
  }

  function h(tag, attrs, kids) { return build(root.document.createElement(tag), attrs, kids, false); }
  function hs(tag, attrs, kids) { return build(root.document.createElementNS(SVGNS, tag), attrs, kids, true); }

  function clear(el) { while (el.firstChild) el.removeChild(el.firstChild); }

  function actionText(a) { return a === 'allow' ? '허용' : '차단'; }

  function ruleText(r) {
    if (!r) return '—';
    return '#' + r.no + ' ' + r.src + ' → ' + r.dst + ' / ' + r.service + ' / ' + actionText(r.action);
  }

  function errorsText(errors) {
    return errors.map(function (e) {
      var label = e.ruleNo ? '규칙 ' + e.ruleNo + ' ' : '';
      return label + (FIELD_LABEL[e.field] || e.field) + ': ' + e.message;
    }).join(' / ');
  }

  // ---------- 저장 ----------
  function storageGet(key) {
    try { return root.localStorage.getItem(key); } catch (e) { return null; }
  }
  function storageSet(key, value) {
    try { root.localStorage.setItem(key, value); } catch (e) { /* 저장 불가 환경이면 메모리에서만 동작 */ }
  }
  function storageRemove(key) {
    try { root.localStorage.removeItem(key); } catch (e) { /* 무시 */ }
  }

  function loadSaved() {
    var raw = storageGet(STORAGE_KEY);
    if (!raw) return null;
    try {
      var data = JSON.parse(raw);
      if (!data || !Array.isArray(data.rules) || !Array.isArray(data.history)) return null;
      if (!PW.validator.validatePolicy(data.rules).ok) return null;
      return data;
    } catch (e) {
      return null;
    }
  }

  // ---------- 시작 ----------
  function init(app) {
    var state = { policy: null, by: storageGet(BY_KEY) || '', editing: null, analysis: null, judged: null };

    function makePolicy(saved) {
      return PW.policy.create({
        rules: saved ? saved.rules : undefined,
        entries: saved ? saved.history : undefined,
        onChange: function (s) { storageSet(STORAGE_KEY, JSON.stringify(s)); }
      });
    }
    state.policy = makePolicy(loadSaved());

    clear(app);

    // ----- 머리말 -----
    var byInput = h('input', { type: 'text', id: 'by', placeholder: '이름', value: state.by,
      oninput: function () { state.by = byInput.value; storageSet(BY_KEY, state.by); } });
    var resetBtn = h('button', { type: 'button', id: 'reset', className: 'danger', text: '정책표·이력 초기화',
      onclick: function () {
        if (!root.confirm('정책표를 기본 5행으로 되돌리고 변경 이력을 모두 지웁니다. 계속할까요?')) return;
        storageRemove(STORAGE_KEY);
        state.policy = makePolicy(null);
        state.editing = null; state.analysis = null; state.judged = null;
        cancelEdit();
        renderAll();
      } });
    app.appendChild(h('header', {}, [
      h('h1', { text: '패킷 길찾기' }),
      h('p', { className: 'sub', text: '방화벽 정책 시뮬레이터 — 위에서부터 처음 일치하는 규칙 하나만 적용한다 [SPEC 1-1-1]' }),
      h('div', { className: 'bar' }, [h('label', { for: 'by' }, ['변경자 ', byInput]), resetBtn])
    ]));

    // ----- 토폴로지 -----
    var topoBox = h('div', { id: 'topology' });
    app.appendChild(h('section', {}, [h('h2', {}, ['토폴로지 ', h('span', { className: 'tag', text: '[1-4-4]' })]), topoBox]));

    // ----- 정책표 -----
    var tableBox = h('div', { id: 'policy-table' });
    var tableMsg = h('p', { id: 'table-msg', className: 'msg' });
    var checkBtn = h('button', { type: 'button', id: 'check', text: '정책 점검', onclick: function () {
      state.analysis = PW.analyzer.analyze(state.policy.rules());
      renderTable(); renderCheck();
    } });

    var fSrc = h('input', { type: 'text', id: 'f-src', list: 'dl-addr', placeholder: 'Any / 구역 / 그룹 / IP' });
    var fDst = h('input', { type: 'text', id: 'f-dst', list: 'dl-addr', placeholder: 'Any / 구역 / 그룹 / IP' });
    var fService = h('input', { type: 'text', id: 'f-service', placeholder: 'Any 또는 TCP 80,443' });
    var fAction = h('select', { id: 'f-action', value: 'allow' }, [
      h('option', { value: 'allow', text: '허용' }), h('option', { value: 'deny', text: '차단' })]);
    var fPurpose = h('input', { type: 'text', id: 'f-purpose', placeholder: '목적' });
    var fPos = h('input', { type: 'number', id: 'f-pos', min: '1', placeholder: '맨 아래' });
    var formTitle = h('h3', { text: '규칙 추가' });
    var submitBtn = h('button', { type: 'submit', id: 'f-submit', text: '추가' });
    var cancelBtn = h('button', { type: 'button', id: 'f-cancel', text: '취소', onclick: function () { cancelEdit(); } });
    var posLabel = h('label', {}, ['위치(번호) ', fPos]);
    var formMsg = h('p', { id: 'form-msg', className: 'msg error' });

    function fillForm(r) {
      fSrc.value = r ? r.src : '';
      fDst.value = r ? r.dst : '';
      fService.value = r ? r.service : '';
      fAction.value = r ? r.action : 'allow';
      fPurpose.value = r ? r.purpose : '';
      fPos.value = '';
    }

    function cancelEdit() {
      state.editing = null;
      fillForm(null);
      formTitle.textContent = '규칙 추가';
      submitBtn.textContent = '추가';
      cancelBtn.className = 'hidden';
      posLabel.className = '';
      formMsg.textContent = '';
    }

    function startEdit(r) {
      state.editing = r.no;
      fillForm(r);
      formTitle.textContent = '규칙 ' + r.no + ' 수정';
      submitBtn.textContent = '수정 저장';
      cancelBtn.className = '';
      posLabel.className = 'hidden';
      formMsg.textContent = '';
    }

    var form = h('form', { id: 'rule-form', onsubmit: function (ev) {
      if (ev && ev.preventDefault) ev.preventDefault();
      var content = { src: fSrc.value, dst: fDst.value, service: fService.value, action: fAction.value, purpose: fPurpose.value };
      var res;
      if (state.editing !== null) {
        res = state.policy.edit(state.editing, content, state.by);
      } else {
        var posText = String(fPos.value).trim();
        res = state.policy.add(content, state.by, posText === '' ? undefined : Number(posText));
      }
      if (!res.ok) { formMsg.textContent = errorsText(res.errors); return; }
      cancelEdit();
      afterChange();
    } }, [
      formTitle,
      h('div', { className: 'grid' }, [
        h('label', {}, ['출발지 ', fSrc]), h('label', {}, ['목적지 ', fDst]),
        h('label', {}, ['서비스 ', fService]), h('label', {}, ['동작 ', fAction]),
        h('label', {}, ['목적 ', fPurpose]), posLabel
      ]),
      h('div', { className: 'bar' }, [submitBtn, cancelBtn]),
      formMsg
    ]);
    cancelBtn.className = 'hidden';

    var dl = h('datalist', { id: 'dl-addr' }, ['Any'].concat(
      topo.zones.map(function (z) { return z.name; }),
      topo.groups.map(function (g) { return g.name; }),
      topo.hosts.map(function (x) { return x.ip; })
    ).map(function (v) { return h('option', { value: v }); }));

    app.appendChild(h('section', {}, [
      h('h2', {}, ['정책표 ', h('span', { className: 'tag', text: '[1-2, 1-1-3]' })]),
      h('div', { className: 'bar' }, [checkBtn]),
      tableBox, tableMsg, form, dl
    ]));

    // ----- 패킷 길찾기 -----
    var pSrc = h('input', { type: 'text', id: 'p-src', list: 'dl-ip', placeholder: '예: 203.0.113.10' });
    var pDst = h('input', { type: 'text', id: 'p-dst', list: 'dl-ip', placeholder: '예: 172.16.10.10' });
    var pProto = h('select', { id: 'p-proto', value: 'TCP' }, [
      h('option', { value: 'TCP', text: 'TCP' }), h('option', { value: 'UDP', text: 'UDP' })]);
    var pPort = h('input', { type: 'number', id: 'p-port', min: '1', max: '65535', placeholder: '포트' });
    var packetMsg = h('p', { id: 'packet-msg', className: 'msg error' });
    var resultBox = h('div', { id: 'result' });
    var ipList = h('datalist', { id: 'dl-ip' }, topo.hosts.map(function (x) {
      return h('option', { value: x.ip, label: x.name });
    }));

    function setPacket(p) { pSrc.value = p.srcIp; pDst.value = p.dstIp; pProto.value = p.proto; pPort.value = String(p.port); }

    function runJudge() {
      var portText = String(pPort.value).trim();
      var packet = { srcIp: pSrc.value.trim(), dstIp: pDst.value.trim(), proto: pProto.value,
        port: portText === '' ? NaN : Number(portText) };
      var res = PW.engine.judge(state.policy.rules(), packet);
      if (!res.ok) {
        packetMsg.textContent = errorsText(res.errors);
        state.judged = null;
      } else {
        packetMsg.textContent = '';
        state.judged = { packet: packet, result: res };
      }
      renderTopology(); renderTable(); renderResult();
    }

    app.appendChild(h('section', {}, [
      h('h2', {}, ['패킷 길찾기 ', h('span', { className: 'tag', text: '[2-1]' })]),
      h('div', { className: 'presets' }, PRESETS.map(function (pr) {
        return h('button', { type: 'button', className: 'preset', text: pr.label,
          onclick: function () { setPacket(pr.p); runJudge(); } });
      })),
      h('div', { className: 'grid' }, [
        h('label', {}, ['출발 IP ', pSrc]), h('label', {}, ['도착 IP ', pDst]),
        h('label', {}, ['프로토콜 ', pProto]), h('label', {}, ['포트 ', pPort])
      ]),
      h('div', { className: 'bar' }, [h('button', { type: 'button', id: 'judge', text: '판정', onclick: runJudge })]),
      packetMsg, resultBox, ipList
    ]));

    // ----- 정책 점검 결과 -----
    var checkBox = h('div', { id: 'check-result' });
    app.appendChild(h('section', {}, [
      h('h2', {}, ['정책 점검 결과 ', h('span', { className: 'tag', text: '[2-2~2-4, 2-6, 1-5-2]' })]),
      checkBox
    ]));

    // ----- 변경 이력 -----
    var historyBox = h('div', { id: 'history' });
    app.appendChild(h('section', {}, [
      h('h2', {}, ['변경 이력 ', h('span', { className: 'tag', text: '[2-5, 1-3-4]' })]),
      historyBox
    ]));

    // ---------- 그리기 ----------
    function afterChange() {
      state.analysis = null;
      state.judged = null;
      packetMsg.textContent = '';
      renderAll();
    }

    function renderAll() {
      renderTopology(); renderTable(); renderResult(); renderCheck(); renderHistory();
    }

    var ZONE_POS = { '인터넷': [10, 10], 'DMZ': [430, 10], '내부망': [10, 260], '개발·운영 서버망': [430, 260] };
    var ZONE_LINE = {
      '인터넷': [210, 60, 270, 150], 'DMZ': [430, 60, 370, 150],
      '내부망': [210, 310, 270, 210], '개발·운영 서버망': [430, 310, 370, 210]
    };

    function renderTopology() {
      clear(topoBox);
      var j = state.judged;
      var res = j ? j.result : null;
      var kind = res ? (res.action === 'allow' ? 'allow' : 'deny') : '';
      var kids = [];

      topo.zones.forEach(function (z) {
        var l = ZONE_LINE[z.name];
        var on = res && (z.name === res.srcZone || z.name === res.dstZone);
        kids.push(hs('line', { x1: l[0], y1: l[1], x2: l[2], y2: l[3],
          className: 'link' + (on ? ' on-' + kind : '') }));
      });

      topo.zones.forEach(function (z) {
        var p = ZONE_POS[z.name];
        var isSrc = res && z.name === res.srcZone, isDst = res && z.name === res.dstZone;
        var tag = [isSrc ? '출발' : null, isDst ? '도착' : null].filter(Boolean).join('·');
        var hostsHere = topo.hosts.filter(function (x) { return topo.zoneOf(x.ip) === z.name; });
        kids.push(hs('g', {}, [
          hs('rect', { x: p[0], y: p[1], width: 200, height: 110, rx: 8,
            className: 'zone' + (isSrc ? ' src' : '') + (isDst ? ' dst' : '') }),
          hs('text', { x: p[0] + 10, y: p[1] + 18, className: 'zname', text: z.name }),
          hs('text', { x: p[0] + 10, y: p[1] + 32, className: 'zcidr', text: z.cidr || '그 밖의 모든 IP' }),
          tag ? hs('text', { x: p[0] + 190, y: p[1] + 18, className: 'ztag', 'text-anchor': 'end', text: tag }) : null,
          hostsHere.map(function (x, i) {
            return hs('text', { x: p[0] + 10, y: p[1] + 49 + i * 13, className: 'zhost', text: x.name + ' ' + x.ip });
          })
        ]));
      });

      kids.push(hs('rect', { x: 250, y: 150, width: 140, height: 60, rx: 8,
        className: 'fw' + (kind ? ' ' + kind : '') }));
      kids.push(hs('text', { x: 320, y: 175, 'text-anchor': 'middle', className: 'fwname', text: '방화벽' }));
      kids.push(hs('text', { x: 320, y: 196, 'text-anchor': 'middle', className: 'fwverdict',
        text: res ? (actionText(res.action) + (res.matched ? ' (규칙 ' + res.matched + ')' : ' (암묵적)')) : '정책 적용' }));

      topoBox.appendChild(hs('svg', { viewBox: '0 0 640 380', role: 'img', 'aria-label': '4구역 토폴로지', className: 'topo' }, kids));
    }

    function warningsFor(no, isLast) {
      if (!state.analysis) return [];
      return state.analysis.warnings.filter(function (w) {
        return w.ruleNo === no || (w.type === 'default-deny' && isLast);
      });
    }

    function traceClass(no) {
      var j = state.judged;
      if (!j) return '';
      var t = j.result.trace.filter(function (x) { return x.no === no; })[0];
      if (!t) return 'unseen';
      if (t.matched) return t.action === 'allow' ? 'hit-allow' : 'hit-deny';
      return 'skip';
    }

    function renderTable() {
      clear(tableBox);
      var rules = state.policy.rules();
      var rows = rules.map(function (r, i) {
        var last = i === rules.length - 1;
        var badges = warningsFor(r.no, last).map(function (w) {
          return h('span', { className: 'badge ' + w.type, title: w.message, text: WARN_LABEL[w.type] });
        });
        return h('tr', { className: traceClass(r.no) }, [
          h('td', { text: r.no }), h('td', { text: r.src }), h('td', { text: r.dst }), h('td', { text: r.service }),
          h('td', { className: 'act-' + r.action, text: actionText(r.action) }),
          h('td', { text: r.purpose }),
          h('td', {}, badges),
          h('td', { className: 'ops' }, [
            h('button', { type: 'button', className: 'op-up', title: '위로', text: '↑', disabled: i === 0,
              onclick: function () { doMove(r.no, r.no - 1); } }),
            h('button', { type: 'button', className: 'op-down', title: '아래로', text: '↓', disabled: last,
              onclick: function () { doMove(r.no, r.no + 1); } }),
            h('button', { type: 'button', className: 'op-edit', text: '수정', onclick: function () { startEdit(r); } }),
            h('button', { type: 'button', className: 'op-del danger', text: '삭제', onclick: function () { doRemove(r); } })
          ])
        ]);
      });
      tableBox.appendChild(h('table', {}, [
        h('thead', {}, [h('tr', {}, ['번호', '출발지', '목적지', '서비스', '동작', '목적', '경고', '작업']
          .map(function (t) { return h('th', { text: t }); }))]),
        h('tbody', {}, rows)
      ]));
    }

    function doMove(no, to) {
      var res = state.policy.move(no, to, state.by);
      if (!res.ok) { tableMsg.textContent = errorsText(res.errors); return; }
      tableMsg.textContent = '';
      cancelEdit();
      afterChange();
    }

    function doRemove(r) {
      if (!root.confirm('규칙 ' + r.no + ' 을(를) 삭제할까요?')) return;
      var res = state.policy.remove(r.no, state.by);
      if (!res.ok) { tableMsg.textContent = errorsText(res.errors); return; }
      tableMsg.textContent = '';
      cancelEdit();
      afterChange();
    }

    function renderResult() {
      clear(resultBox);
      var j = state.judged;
      if (!j) return;
      var res = j.result;
      var allow = res.action === 'allow';
      var rules = state.policy.rules();
      var matchedRule = rules.filter(function (r) { return r.no === res.matched; })[0];

      resultBox.appendChild(h('div', { className: 'verdict ' + (allow ? 'allow' : 'deny') }, [
        h('strong', { text: allow ? '허용' : '차단' }),
        ' ',
        res.matched !== null ? '— 규칙 ' + res.matched + ' 에서 멈춤 (첫 일치)' : '— 일치하는 규칙 없음(암묵적 차단)',
        h('div', { className: 'route', text: res.srcZone + ' → 방화벽 → ' + res.dstZone })
      ]));
      if (matchedRule) resultBox.appendChild(h('p', { className: 'matched', text: ruleText(matchedRule) }));
      res.warnings.forEach(function (w) { resultBox.appendChild(h('p', { className: 'warn', text: '⚠ ' + w })); });

      resultBox.appendChild(h('table', { className: 'trace' }, [
        h('thead', {}, [h('tr', {}, ['비교한 규칙', '동작', '결과', '불일치 항목'].map(function (t) { return h('th', { text: t }); }))]),
        h('tbody', {}, res.trace.map(function (t) {
          return h('tr', { className: t.matched ? (t.action === 'allow' ? 'hit-allow' : 'hit-deny') : 'skip' }, [
            h('td', { text: '규칙 ' + t.no }), h('td', { text: actionText(t.action) }),
            h('td', { text: t.matched ? '일치 → 적용' : '불일치' }),
            h('td', { text: t.mismatch.join(', ') })
          ]);
        }))
      ]));
      resultBox.appendChild(h('p', { className: 'note', text: '일치한 규칙 아래는 비교하지 않는다 [1-1-1].' }));
    }

    function renderCheck() {
      clear(checkBox);
      if (!state.analysis) {
        checkBox.appendChild(h('p', { className: 'note', text: "'정책 점검' 버튼을 누르면 기본 거부·섀도잉·중복·syslog 포트를 검사한다." }));
        return;
      }
      var ws = state.analysis.warnings;
      if (ws.length === 0) {
        checkBox.appendChild(h('p', { className: 'ok', text: '경고 없음 — 점검 통과' }));
        return;
      }
      checkBox.appendChild(h('ul', {}, ws.map(function (w) {
        return h('li', {}, [h('span', { className: 'badge ' + w.type, text: WARN_LABEL[w.type] }), ' ' + w.message]);
      })));
    }

    function renderHistory() {
      clear(historyBox);
      var list = state.policy.history.recent();
      if (list.length === 0) {
        historyBox.appendChild(h('p', { className: 'note', text: '아직 변경 이력이 없습니다.' }));
        return;
      }
      historyBox.appendChild(h('table', {}, [
        h('thead', {}, [h('tr', {}, ['시각', '종류', '규칙', '변경 전', '변경 후', '변경자']
          .map(function (t) { return h('th', { text: t }); }))]),
        h('tbody', {}, list.map(function (e) {
          return h('tr', {}, [
            h('td', { text: e.time }), h('td', { text: TYPE_LABEL[e.type] || e.type }), h('td', { text: e.ruleNo }),
            h('td', { text: ruleText(e.before) }), h('td', { text: ruleText(e.after) }), h('td', { text: e.by })
          ]);
        }))
      ]));
    }

    renderAll();
    return state;
  }

  var api = { init: init };
  root.PW.ui = api;
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
})(typeof globalThis !== 'undefined' ? globalThis : this);
