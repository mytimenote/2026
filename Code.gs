// ============================================================
//  졸업앨범 음성 녹음 서버 — [재설계 0단계: 토대]
//  ------------------------------------------------------------
//  구조 개요
//   · registry (마스터 시트, 단일):
//       school | ssId | folderId | pwHash | pwSalt |
//       downloadEnabled | startDate | endDate |
//       gradYear | retainUntil | createdAt
//     → 학교명으로 "그 학교의 스프레드시트ID/폴더ID/비번해시"만 조회
//   · 학교별 스프레드시트 (학교당 1개, 자동 생성):
//       시트 'recordings': timestamp | name | class | fileName | fileId | mimeType
//     → 어떤 요청이 와도 해당 학교 시트 하나만 읽음 (4번 해결)
//
//  이 0단계 파일은 "토대 함수"만 정의합니다.
//  doGet/doPost 연결과 기존 로직 이식은 1단계 이후 진행합니다.
// ============================================================

// ------------------------------------------------------------
//  설정값
// ------------------------------------------------------------
var REGISTRY_SS_ID  = '';            // ← registry 마스터 스프레드시트 ID (initSetup 실행 후 채움)
var REGISTRY_SHEET  = 'registry';
var SCHOOL_REC_SHEET = 'recordings'; // 학교별 스프레드시트 안의 시트 이름
var ROOT_FOLDER_NAME = '졸업앨범_음성';

// Script Properties 키 이름 (값은 코드에 하드코딩하지 않음)
var PROP_HMAC_KEY    = 'HMAC_SECRET';   // 토큰 서명용 비밀키
var PROP_ADMIN_HASH  = 'ADMIN_PW_HASH'; // 관리자 비번 해시
var PROP_ADMIN_SALT  = 'ADMIN_PW_SALT'; // 관리자 비번 salt
var PROP_REGISTRY_ID = 'REGISTRY_SS_ID';// registry 스프레드시트 ID
var PROP_ACTIVE_KID  = 'HMAC_ACTIVE_KID';   // 현재 서명에 쓰는 키 버전 (기본 v1)
var PROP_REVOKED_KIDS= 'HMAC_REVOKED_KIDS'; // 폐기된 키 버전 목록 (쉼표 구분)
var PROP_ROOT_FOLDER_ID = 'ROOT_FOLDER_ID'; // 관리자 설정에서 지정하는 신규 학교 저장 폴더

// 토큰 유효시간 (분)
var TOKEN_TTL_ADMIN  = 120;  // 관리자 2시간
var TOKEN_TTL_SCHOOL = 180;  // 학교(교사) 3시간

// ============================================================
//  [A] 최초 1회 설정 — 에디터에서 수동 실행
// ============================================================
//  initSetup() 을 한 번 실행하면:
//   1) registry 스프레드시트 생성 → ID를 Script Properties에 저장
//   2) HMAC 비밀키 생성 → 저장
//  실행 후 로그에 출력되는 REGISTRY_SS_ID 값을 위 REGISTRY_SS_ID 변수에도 붙여넣으세요.
// ------------------------------------------------------------
function initSetup() {
  var props = PropertiesService.getScriptProperties();

  // 1) registry 스프레드시트 생성 (이미 있으면 재사용)
  var regId = props.getProperty(PROP_REGISTRY_ID);
  if (!regId) {
    var ss = SpreadsheetApp.create('졸업앨범_registry');
    var sh = ss.getSheets()[0];
    sh.setName(REGISTRY_SHEET);
    sh.appendRow([
      'school','ssId','folderId','pwHash','pwSalt',
      'downloadEnabled','startDate','endDate',
      'gradYear','retainUntil','createdAt','pwEnc',
      'tPwHash','tPwSalt'
    ]);
    sh.setFrozenRows(1);
    regId = ss.getId();
    props.setProperty(PROP_REGISTRY_ID, regId);
  }

  // 2) HMAC 비밀키 생성 (없을 때만)
  if (!props.getProperty(PROP_HMAC_KEY)) {
    props.setProperty(PROP_HMAC_KEY, _randomToken(48));
  }

  Logger.log('[initSetup 완료]');
  Logger.log('REGISTRY_SS_ID = ' + regId);
  Logger.log('→ 위 값을 코드 상단 REGISTRY_SS_ID 변수에 붙여넣으세요.');
  Logger.log('관리자 비밀번호는 setAdminPassword("원하는비번") 를 따로 실행해 설정하세요.');
}

// 관리자 비밀번호 설정 — 에디터에서 setAdminPassword('실제비번') 형태로 1회 실행
function setAdminPassword(plainPw) {
  if (!plainPw) { Logger.log('비밀번호를 인자로 넣으세요. 예) setAdminPassword("mypw")'); return; }
  var props = PropertiesService.getScriptProperties();
  var salt  = _randomToken(16);
  var hash  = _hashPassword(plainPw, salt);
  props.setProperty(PROP_ADMIN_SALT, salt);
  props.setProperty(PROP_ADMIN_HASH, hash);
  Logger.log('[관리자 비밀번호 설정 완료]');
}
// ============================================================
//  [A-2] 서명 키 버전 관리 — 에디터에서 수동 실행
//  · rotateSigningKey(): 새 버전 키 생성 + 활성화 (매년 앨범 인쇄 전 1회 권장)
//    → 이후 발급되는 QR은 새 키, 기존 인쇄 QR은 옛 키로 계속 검증됨
//  · revokeSigningKey('v2'): 유출 사고 시 해당 버전만 무효화 (비상용)
//  · listSigningKeys(): 현재 키 현황 확인
// ============================================================
function rotateSigningKey() {
  var props = PropertiesService.getScriptProperties();
  var cur  = _activeKid();
  var n    = parseInt(String(cur).replace('v', ''), 10) || 1;
  var next = 'v' + (n + 1);
  props.setProperty('HMAC_KEY_' + next, _randomToken(48));
  props.setProperty(PROP_ACTIVE_KID, next);
  Logger.log('서명 키 교체 완료: ' + cur + ' → ' + next);
  Logger.log('기존 키는 검증용으로 유지됩니다 (인쇄된 QR 계속 재생 가능).');
}

function revokeSigningKey(kid) {
  if (!kid) { Logger.log('예) revokeSigningKey("v2")'); return; }
  if (kid === _activeKid()) {
    Logger.log('⚠ 현재 활성 키는 폐기할 수 없습니다. 먼저 rotateSigningKey()로 교체하세요.');
    return;
  }
  var props = PropertiesService.getScriptProperties();
  var raw = props.getProperty(PROP_REVOKED_KIDS) || '';
  var list = raw ? raw.split(',') : [];
  if (list.indexOf(kid) === -1) list.push(kid);
  props.setProperty(PROP_REVOKED_KIDS, list.join(','));
  Logger.log('키 폐기 완료: ' + kid + ' — 이 키로 서명된 모든 토큰/QR이 즉시 무효화됩니다.');
}

function listSigningKeys() {
  var props = PropertiesService.getScriptProperties();
  var keys = props.getKeys();
  Logger.log('활성 키: ' + _activeKid());
  Logger.log('폐기 목록: ' + (props.getProperty(PROP_REVOKED_KIDS) || '(없음)'));
  Logger.log('v1: ' + (props.getProperty(PROP_HMAC_KEY) ? '있음' : '없음'));
  for (var i = 0; i < keys.length; i++) {
    if (keys[i].indexOf('HMAC_KEY_v') === 0) Logger.log(keys[i].replace('HMAC_KEY_', '') + ': 있음');
  }
}

// ============================================================
//  [B] 비밀번호 해시 / 검증 — 3번
// ============================================================
//  salt + SHA-256 반복 해시. (GAS에 bcrypt가 없어 SHA-256 다중 라운드로 강화)
function _hashPassword(plain, salt) {
  var rounds = 1000;
  var data = salt + '::' + plain;
  var bytes = null;
  for (var i = 0; i < rounds; i++) {
    bytes = Utilities.computeDigest(
      Utilities.DigestAlgorithm.SHA_256,
      (bytes ? _bytesToHex(bytes) : data) + salt
    );
  }
  return _bytesToHex(bytes);
}

// 상수시간 비교 — 타이밍 공격 방어 (10번)
function _constantTimeEquals(a, b) {
  a = String(a); b = String(b);
  if (a.length !== b.length) return false;
  var diff = 0;
  for (var i = 0; i < a.length; i++) {
    diff |= (a.charCodeAt(i) ^ b.charCodeAt(i));
  }
  return diff === 0;
}

// 평문이 저장된 해시와 일치하는지 검증
function _verifyPassword(plain, salt, expectedHash) {
  if (!salt || !expectedHash) return false;
  var actual = _hashPassword(plain, salt);
  return _constantTimeEquals(actual, expectedHash);
}

// ============================================================
//  [B-3] 짧은 코드 시스템 (QR / 카톡 링크 단순화)
//  - codes 시트: code | type('school'|'student') | school | fileId | createdAt
//  - 코드: 영숫자 6자 (혼동 문자 제외). 충돌 시 재생성.
// ============================================================
var CODES_SHEET = 'codes';
var CODE_ALPHABET = '23456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz'; // 0,O,1,I,l,o 제외
var CODE_LEN = 6;

// codes 시트 핸들 (없으면 registry 스프레드시트 안에 생성)
function _getCodesSheet() {
  var ss = SpreadsheetApp.openById(
    REGISTRY_SS_ID || PropertiesService.getScriptProperties().getProperty(PROP_REGISTRY_ID)
  );
  var sh = ss.getSheetByName(CODES_SHEET);
  if (!sh) {
    sh = ss.insertSheet(CODES_SHEET);
    sh.appendRow(['code','type','school','fileId','createdAt']);
    sh.setFrozenRows(1);
  }
  return sh;
}

// 랜덤 코드 1개 생성 (HMAC seed 혼합)
function _genCodeString(seed) {
  var raw = _sign(String(seed) + '|' + Utilities.getUuid() + '|' + Date.now());
  // raw(hex)를 알파벳으로 매핑
  var out = '';
  for (var i = 0; i < raw.length && out.length < CODE_LEN; i += 2) {
    var n = parseInt(raw.substr(i, 2), 16);
    out += CODE_ALPHABET.charAt(n % CODE_ALPHABET.length);
  }
  // 혹시 부족하면 랜덤 패딩
  while (out.length < CODE_LEN) {
    out += CODE_ALPHABET.charAt(Math.floor(Math.random() * CODE_ALPHABET.length));
  }
  return out;
}

// 유니크한 코드 발급 (중복 회피)
function _issueCode(type, school, fileId) {
  var sh = _getCodesSheet();
  var existing = {};
  var vals = sh.getDataRange().getValues();
  for (var i = 1; i < vals.length; i++) existing[String(vals[i][0])] = true;
  var code;
  var tries = 0;
  do {
    code = _genCodeString(type + '|' + school + '|' + (fileId || '') + '|' + tries);
    tries++;
  } while (existing[code] && tries < 50);
  sh.appendRow([code, type, school, fileId || '', new Date()]);
  return code;
}

// 학교 코드 조회 (이미 있으면 재사용, 없으면 발급)
function _getOrIssueSchoolCode(school) {
  var sh = _getCodesSheet();
  var vals = sh.getDataRange().getValues();
  for (var i = 1; i < vals.length; i++) {
    if (vals[i][1] === 'school' && String(vals[i][2]).trim() === String(school).trim()) {
      return String(vals[i][0]);
    }
  }
  return _issueCode('school', school, '');
}

// 학생 코드 조회 (fileId 기준, 있으면 재사용)
function _getOrIssueStudentCode(school, fileId) {
  var sh = _getCodesSheet();
  var vals = sh.getDataRange().getValues();
  for (var i = 1; i < vals.length; i++) {
    if (vals[i][1] === 'student' && String(vals[i][3]) === String(fileId)) {
      return String(vals[i][0]);
    }
  }
  return _issueCode('student', school, fileId);
}

// 코드 → 매핑 정보 조회
function _lookupCode(code) {
  if (!code) return null;
  var sh = _getCodesSheet();
  var vals = sh.getDataRange().getValues();
  for (var i = 1; i < vals.length; i++) {
    if (String(vals[i][0]) === String(code)) {
      return { code: String(vals[i][0]), type: vals[i][1], school: String(vals[i][2]).trim(), fileId: String(vals[i][3]) };
    }
  }
  return null;
}

// ============================================================
//  [C] 토큰 발급 / 검증 (HMAC 서명) — 1·2번 토대
// ============================================================
//  토큰 형식:  base64url(payloadJson) + '.' + base64url(hmac)
//  payload: { scope:'admin'|'school', school:'...', exp: <ms> }
function _issueToken(scope, school, ttlMinutes) {
  var payload = {
    scope: scope,
    school: school || '',
    kid: _activeKid(),
    exp: Date.now() + ttlMinutes * 60 * 1000
  };
  var body = _b64url(JSON.stringify(payload));
  var sig  = _sign(body);
  return body + '.' + sig;
}

//  토큰 검증 → 성공 시 payload 객체, 실패 시 null
//  requiredScope 지정 시 scope 불일치도 실패
function _verifyToken(token, requiredScope) {
  try {
    if (!token || token.indexOf('.') === -1) return null;
    var parts = token.split('.');
    var body = parts[0], sig = parts[1];
    var payload = JSON.parse(_b64urlDecode(body));
    var kid = payload.kid || 'v1';                            // 구형 토큰 호환
    if (_isRevokedKid(kid)) return null;                      // 폐기된 키 거부
    if (!_keyForKid(kid)) return null;
    if (!_constantTimeEquals(sig, _signWith(kid, body))) return null; // 서명 위조
    if (Date.now() > payload.exp) return null;                // 만료
    if (requiredScope && payload.scope !== requiredScope) return null;
    return payload;
  } catch (e) {
    return null;
  }
}

// ── 키 버전(kid) 관리 ──
// v1 = 기존 HMAC_SECRET (라벨 없는 구형 토큰과의 호환용)
// v2 이후 = Script Properties의 'HMAC_KEY_v2', 'HMAC_KEY_v3' ...
function _keyForKid(kid) {
  var props = PropertiesService.getScriptProperties();
  if (kid === 'v1') return props.getProperty(PROP_HMAC_KEY);
  if (!/^v\d+$/.test(String(kid))) return null;
  return props.getProperty('HMAC_KEY_' + kid);
}

function _activeKid() {
  return PropertiesService.getScriptProperties().getProperty(PROP_ACTIVE_KID) || 'v1';
}

function _isRevokedKid(kid) {
  var raw = PropertiesService.getScriptProperties().getProperty(PROP_REVOKED_KIDS) || '';
  return raw.split(',').indexOf(String(kid)) !== -1;
}

function _signWith(kid, text) {
  var key = _keyForKid(kid);
  if (!key) throw new Error('서명 키 없음: ' + kid);
  return _bytesToHex(Utilities.computeHmacSha256Signature(text, key));
}

// 기존 호출부 호환: 항상 "현재 활성 키"로 서명
function _sign(text) {
  return _signWith(_activeKid(), text);
}

// ============================================================
//  [D] registry 접근 헬퍼 — 4번 토대
// ============================================================
function _getRegistrySheet() {
  var id = REGISTRY_SS_ID ||
           PropertiesService.getScriptProperties().getProperty(PROP_REGISTRY_ID);
  if (!id) throw new Error('REGISTRY 미설정 — initSetup()을 먼저 실행하세요.');
  var ss = SpreadsheetApp.openById(id);
  var sh = ss.getSheetByName(REGISTRY_SHEET);
  if (!sh) throw new Error('registry 시트를 찾을 수 없습니다.');
  return sh;
}

// 학교명으로 registry 행 객체 반환 (없으면 null)
//  반환: { row:<1기준 행번호>, school, ssId, folderId, pwHash, pwSalt,
//          downloadEnabled, startDate, endDate, gradYear, retainUntil }
function _findSchool(school) {
  var sh = _getRegistrySheet();
  var values = sh.getDataRange().getValues();
  var target = String(school || '').trim();
  for (var i = 1; i < values.length; i++) {
    if (String(values[i][0]).trim() === target) {
      return {
        row: i + 1,
        school: values[i][0],
        ssId: values[i][1],
        folderId: values[i][2],
        pwHash: values[i][3],
        pwSalt: values[i][4],
        downloadEnabled: !(values[i][5] === false || String(values[i][5]).toLowerCase() === 'false'),
        startDate: values[i][6],
        endDate: values[i][7],
        gradYear: values[i][8],
        retainUntil: values[i][9],
        tPwHash: values[i][12] ? String(values[i][12]) : '',
        tPwSalt: values[i][13] ? String(values[i][13]) : ''
      };
    }
  }
  return null;
}

// 학교별 스프레드시트의 recordings 시트 핸들 반환
function _getSchoolRecSheet(ssId) {
  var ss = SpreadsheetApp.openById(ssId);
  var sh = ss.getSheetByName(SCHOOL_REC_SHEET);
  if (!sh) {
    sh = ss.insertSheet(SCHOOL_REC_SHEET);
    sh.appendRow(['timestamp','name','class','fileName','fileId','mimeType']);
    sh.setFrozenRows(1);
  }
  return sh;
}

// ============================================================
//  [D-2] 학교 등록 / 수정 / 삭제 / 목록 — 1단계
//  ------------------------------------------------------------
//  이 단계 함수들은 모두 "관리자 토큰"이 필요합니다.
//  토큰 검증은 doPost(2단계)에서 수행하고, 여기서는
//  검증이 끝났다는 전제로 호출되는 내부 로직만 둡니다.
// ============================================================

// 학교 등록(신규) 또는 수정(기존)
//  data: { school, password, startDate, endDate, gradYear, retainUntil }
//   · 신규: 전용 스프레드시트 + Drive 폴더 자동 생성, 비번 해시 저장
//   · 기존: 비번(입력 시에만 갱신)·기간·보관정보 갱신
//  ※ 기존 setPassword(data) 를 대체 (함수명 변경)
function registerOrUpdateSchool(data) {
  var school     = String(data.school || '').trim();
  var password   = String(data.password || '').trim();
  var startDate  = String(data.startDate || '').trim();
  var endDate    = String(data.endDate || '').trim();
  var gradYear   = String(data.gradYear || '').trim();
  var retainUntil= String(data.retainUntil || '').trim();
  var teacherPw  = String(data.teacherPassword || '').trim();

  if (!school) return makeJson({ success: false, error: '학교명을 입력하세요' });

  var lock = LockService.getScriptLock();
  try {
    lock.waitLock(10000); // 동시 등록 충돌 방지
  } catch (le) {
    return makeJson({ success: false, error: '잠시 후 다시 시도해 주세요(서버 혼잡)' });
  }

  try {
    var sh  = _getRegistrySheet();
    var existing = _findSchool(school);

    if (existing) {
      // ── 기존 학교 수정 ──
      var r = existing.row;
      // 비번은 입력했을 때만 갱신 (빈 값이면 기존 유지)
      if (password) {
        var salt = _randomToken(16);
        var hash = _hashPassword(password, salt);
        sh.getRange(r, 4).setValue(hash); // pwHash
        sh.getRange(r, 5).setValue(salt); // pwSalt
        sh.getRange(r, 12).setValue(''); // pwEnc 사용 중단 — 평문 복원 가능 저장 금지
      }
      if (teacherPw) {
        var tSalt = _randomToken(16);
        var tHash = _hashPassword(teacherPw, tSalt);
        sh.getRange(r, 13).setValue(tHash); // tPwHash
        sh.getRange(r, 14).setValue(tSalt); // tPwSalt
      }
      sh.getRange(r, 7).setValue(startDate);   // startDate
      sh.getRange(r, 8).setValue(endDate);     // endDate
      sh.getRange(r, 9).setValue(gradYear);    // gradYear
      sh.getRange(r, 10).setValue(retainUntil);// retainUntil
      return makeJson({ success: true, updated: true });
    }

    // ── 신규 학교 등록 ──
    if (!password) return makeJson({ success: false, error: '신규 등록 시 비밀번호는 필수입니다' });

    // 1) Drive 폴더 생성 (연도별 루트 폴더 아래 학교 폴더)
    //    예: 2026_졸업앨범_음성 / ○○초등학교
    var configuredRootId = PropertiesService.getScriptProperties().getProperty(PROP_ROOT_FOLDER_ID);
    var yearForFolder = gradYear || String(new Date().getFullYear());
    var rootName      = yearForFolder + '_' + ROOT_FOLDER_NAME;
    // 관리자가 저장 폴더를 지정하면 신규 학교는 그 폴더 아래에 만들고,
    // 설정이 없을 때만 기존 연도별 루트 폴더 동작을 사용합니다.
    var rootFolder    = configuredRootId
      ? DriveApp.getFolderById(configuredRootId)
      : _getOrCreateFolder(DriveApp.getRootFolder(), rootName);
    var schoolFolder  = _getOrCreateFolder(rootFolder, school);
    var folderId      = schoolFolder.getId();

    // 2) 전용 스프레드시트 생성 + recordings 시트 초기화 (학교 폴더 안으로 이동)
    var schoolSs = SpreadsheetApp.create('졸업앨범_' + school);
    var firstSheet = schoolSs.getSheets()[0];
    firstSheet.setName(SCHOOL_REC_SHEET);
    firstSheet.appendRow(['timestamp','name','class','fileName','fileId','mimeType']);
    firstSheet.setFrozenRows(1);
    var ssId = schoolSs.getId();
    // 생성된 시트 파일을 학교 폴더로 이동 (기본은 드라이브 루트에 생성되므로)
    try { DriveApp.getFileById(ssId).moveTo(schoolFolder); } catch (mvErr) {}

    // 3) 비번 해시
    var nSalt = _randomToken(16);
    var nHash = _hashPassword(password, nSalt);

    // 4) registry 행 추가 (pwEnc 자리는 항상 빈 값 — 평문 복원 가능 저장 금지)
    var tSalt2 = '', tHash2 = '';
    if (teacherPw) {
      tSalt2 = _randomToken(16);
      tHash2 = _hashPassword(teacherPw, tSalt2);
    }
    sh.appendRow([
      school, ssId, folderId, nHash, nSalt,
      true, startDate, endDate,
      gradYear, retainUntil, new Date(), '',
      tHash2, tSalt2
    ]);

    var schoolCode = _getOrIssueSchoolCode(school);
    return makeJson({ success: true, created: true, ssId: ssId, folderId: folderId, schoolCode: schoolCode });

  } catch (err) {
    return makeJson({ success: false, error: err.message });
  } finally {
    lock.releaseLock();
  }
}

// 다운로드 허용 토글 (registry 기반)
function setDownloadEnabled(school, enabled) {
  if (!school) return makeJson({ success: false, error: '학교명이 없습니다' });
  var info = _findSchool(school);
  if (!info) return makeJson({ success: false, error: '해당 학교를 찾을 수 없습니다' });
  var sh = _getRegistrySheet();
  sh.getRange(info.row, 6).setValue(enabled === true || enabled === 'true');
  return makeJson({ success: true });
}

// 학교 삭제 — registry 행 + 학교 스프레드시트 + Drive 폴더(휴지통)
//  ※ 기존 deletePasswordRow(school) 를 대체 (함수명 변경)
//  옵션: data.purgeFiles === true 이면 폴더/시트까지 휴지통 이동,
//        아니면 registry 행만 제거(데이터는 보존)
function deleteSchool(school, purgeFiles) {
  if (!school) return makeJson({ success: false, error: '학교명이 없습니다' });
  var info = _findSchool(school);
  if (!info) return makeJson({ success: false, error: '해당 학교를 찾을 수 없습니다' });

  var lock = LockService.getScriptLock();
  try { lock.waitLock(10000); } catch (le) {
    return makeJson({ success: false, error: '잠시 후 다시 시도해 주세요(서버 혼잡)' });
  }

  try {
    if (purgeFiles === true || purgeFiles === 'true') {
      // 학교 스프레드시트 휴지통
      try { if (info.ssId) DriveApp.getFileById(info.ssId).setTrashed(true); } catch (e1) {}
      // 학교 Drive 폴더 휴지통
      try { if (info.folderId) DriveApp.getFolderById(info.folderId).setTrashed(true); } catch (e2) {}
    }
    // registry 행 제거 (최신 행번호 재조회 후 삭제 — 안전)
    var fresh = _findSchool(school);
    if (fresh) _getRegistrySheet().deleteRow(fresh.row);
    return makeJson({ success: true, purged: (purgeFiles === true || purgeFiles === 'true') });
  } catch (err) {
    return makeJson({ success: false, error: err.message });
  } finally {
    lock.releaseLock();
  }
}

// 관리자용 학교 목록 — 비번 해시는 절대 반환하지 않음(평문 노출 차단, 1번)
function getSchoolList() {
  var sh = _getRegistrySheet();
  var values = sh.getDataRange().getValues();
  var list = [];
  for (var i = 1; i < values.length; i++) {
    if (!values[i][0]) continue;
    var schName = String(values[i][0]).trim();
    var schCode = _getOrIssueSchoolCode(schName);  // 학교 코드 (카톡 링크용)
    list.push({
      school:          schName,
      schoolCode:      schCode,
      hasPassword:     !!values[i][3],                 // 학생비번 해시 존재 여부
      hasTeacherPassword: !!values[i][12],             // 관리자 페이지 표시용
      hasTeacherPw:    !!values[i][12],                // 기존 클라이언트 호환
      downloadEnabled: !(values[i][5] === false || String(values[i][5]).toLowerCase() === 'false'),
      startDate:       values[i][6] ? fmtDate(values[i][6]) : '',
      endDate:         values[i][7] ? fmtDate(values[i][7]) : '',
      gradYear:        values[i][8] ? String(values[i][8]) : '',
      retainUntil:     values[i][9] ? fmtDate(values[i][9]) : ''
    });
  }
  list.sort(function(a, b){ return a.school < b.school ? -1 : 1; });
  return makeJson({ schools: list });
}

// 폴더 생성 헬퍼 (기존 getOrCreateFolder 를 내부용으로 이식, 이름 _ 접두)
function _getOrCreateFolder(parent, name) {
  var iter = parent.getFoldersByName(name);
  return iter.hasNext() ? iter.next() : parent.createFolder(name);
}

// ============================================================
//  [F] 무차별 대입 방어 (rate limit) — 10번
//  ------------------------------------------------------------
//  CacheService에 "키별 실패 횟수"를 기록. N회 실패 시 잠금.
//  키는 학교명 기준(IP를 GAS에서 신뢰성 있게 얻기 어려움).
// ============================================================
var RL_MAX_FAILS   = 20;    // 하드 잠금 실패 횟수 (서킷브레이커)
var RL_SOFT_FAILS  = 3;     // 이 횟수부터 응답 지연 시작
var RL_WINDOW_SEC  = 600;   // 실패 카운트 유지 시간(초) = 10분

function _rlKey(scope, id) { return 'rl_' + scope + '_' + id; }

// 실패 누적 시 응답 지연 (무차별 대입 감속) — true면 시도 허용, false면 하드 잠금
function _rlThrottle(scope, id) {
  var cache = CacheService.getScriptCache();
  var raw = cache.get(_rlKey(scope, id));
  var n = raw ? parseInt(raw, 10) : 0;
  if (n >= RL_MAX_FAILS) return false;              // 하드 잠금 (10분)
  if (n >= RL_SOFT_FAILS) {
    var delayMs = Math.min((n - RL_SOFT_FAILS + 1) * 2000, 15000);
    Utilities.sleep(delayMs);                        // 실패 누적에 비례해 지연
  }
  return true;
}

function _rlFail(scope, id) {
  var cache = CacheService.getScriptCache();
  var key = _rlKey(scope, id);
  var raw = cache.get(key);
  var n = (raw ? parseInt(raw, 10) : 0) + 1;
  cache.put(key, String(n), RL_WINDOW_SEC);
  return n;
}

function _rlReset(scope, id) {
  CacheService.getScriptCache().remove(_rlKey(scope, id));
}

// ============================================================
//  [G] 라우팅 — doGet / doPost (2번·8번 토큰 검증 포함)
// ============================================================
function doPost(e) {
  try {
    var data   = JSON.parse(e.postData.contents);
    var action = data.action || 'upload';

    // 공개 QR 재생: 짧은 학생 코드를 검증한 뒤 해당 음성 파일을 반환합니다.
    if (action === 'playQr') return playQr(data.c || '');

    // ── 관리자 로그인 (토큰 발급) — 1번 ──
    if (action === 'adminLogin') return adminLogin(data);

    // ── 관리자 전용 액션 (토큰 필수) ──
    var adminActions = {
      registerSchool: 1, deleteSchool: 1, setDownloadEnabled: 1,
      purgeExpired: 1, setStorageConfig: 1, backupNow: 1, restoreBackup: 1
    };
    if (adminActions[action]) {
      var ap = _verifyToken(data.token, 'admin');
      if (!ap) return makeJson({ success: false, error: 'AUTH_REQUIRED' });
      if (action === 'registerSchool')     return registerOrUpdateSchool(data);
      if (action === 'deleteSchool')        return deleteSchool(data.school, data.purgeFiles);
      if (action === 'setDownloadEnabled')  return setDownloadEnabled(data.school, data.enabled);
      if (action === 'purgeExpired')        return purgeExpired();
      if (action === 'setStorageConfig')    return setStorageConfig(data);
      if (action === 'backupNow')           return backupNow();
      if (action === 'restoreBackup')       return restoreBackup(data.backupFileId);
    }

    // 관리자 페이지는 조회도 POST로 보냅니다. 기존 doGet 경로는 다른 화면과의
    // 호환성을 위해 유지하면서 동일한 관리자 토큰 검증을 적용합니다.
    var adminReadActions = {
      schoolList: 1, storageConfig: 1, prewarm: 1,
      list: 1, playToken: 1, listBackups: 1
    };
    if (adminReadActions[action]) {
      var readAdmin = _verifyToken(data.token, 'admin');
      if (!readAdmin) return makeJson({ success: false, ok: false, error: 'AUTH_REQUIRED' });
      if (action === 'schoolList')    return getSchoolList();
      if (action === 'storageConfig') return storageConfig();
      if (action === 'prewarm')       return prewarm();
      if (action === 'list')          return listRecordings(String(data.school || '').trim());
      if (action === 'playToken')     return issuePlayToken(data.school || '', data.f || '');
      if (action === 'listBackups')   return listBackups();
    }

    // ── 녹음 삭제: 관리자 또는 교사(school 토큰) — 교사 검수용 ──
    if (action === 'deleteRecording') {
      var delAdmin = _verifyToken(data.token, 'admin');
      if (delAdmin) return deleteRecording(data.school, data.fileId);
      var delTeacher = _verifyToken(data.token, 'school');
      if (delTeacher) return deleteRecording(delTeacher.school, data.fileId); // 토큰의 학교로 고정 — 타 학교 삭제 불가
      return makeJson({ success: false, error: 'AUTH_REQUIRED' });
    }

    // ── 학생 로그인 (녹음 전용 record 토큰 발급) ──
    if (action === 'schoolLogin') return schoolLogin(data);

    // ── 교사 로그인 (열람용 school 토큰 발급) ──
    if (action === 'teacherLogin') return teacherLogin(data);

    // ── 음성 업로드 (학생용; 학교 토큰 필요) — 6번 Lock ──
    if (action === 'upload') return uploadRecording(data);

    return makeJson({ success: false, error: '알 수 없는 요청' });
  } catch (err) {
    return makeJson({ success: false, error: err.message });
  }
}

function doGet(e) {
  var action = e.parameter.action || '';

  // 공개 재생: 서명된 play 토큰 필요 (비번 불필요, QR에 토큰 내장) — 2·8번
  if (action === 'play') {
    return playAudio(e.parameter.s || '', e.parameter.f || '', e.parameter.t || '');
  }

  // 공개: 짧은 코드 해석 (QR / 카톡 링크용)
  //  - school 코드  → { type:'school', school }
  //  - student 코드 → { type:'student', school, fileId, t:<재생토큰> }
  if (action === 'resolveCode') {
    return resolveCode(e.parameter.c || '');
  }

  // 공개: 학교 비번 존재/기간 확인용 (비번 자체는 미반환)
  if (action === 'checkPeriod') return checkPeriod(e.parameter.school || '');

  // 학교 토큰 또는 관리자 토큰 필요: 학생 목록 / 메타 / 오디오 스트리밍
  if (action === 'list' || action === 'meta' || action === 'audio') {
    var tok = e.parameter.token;
    var sp = _verifyToken(tok, 'school');
    var ap = sp ? null : _verifyToken(tok, 'admin');
    if (!sp && !ap) return makeJson({ ok: false, error: 'AUTH_REQUIRED' });
    // 학교 토큰이면 토큰의 학교로 고정, 관리자 토큰이면 파라미터의 학교 사용
    var targetSchool = sp ? sp.school : String(e.parameter.school || '').trim();
    if (!targetSchool) return makeJson({ ok: false, error: '학교가 지정되지 않았습니다' });
    if (action === 'list')  return listRecordings(targetSchool);
    if (action === 'meta')  return getMeta(targetSchool, e.parameter.f || '');
    if (action === 'audio') return getAudio(targetSchool, e.parameter.f || '');
  }

  // 관리자 토큰 필요: 학교 목록
  if (action === 'schoolList') {
    var gp = _verifyToken(e.parameter.token, 'admin');
    if (!gp) return makeJson({ ok: false, error: 'AUTH_REQUIRED' });
    return getSchoolList();
  }

  // 관리자 토큰 필요: QR용 play 토큰 발급 (fileId+school에 서명)
  if (action === 'playToken') {
    var pp = _verifyToken(e.parameter.token, 'admin');
    if (!pp) return makeJson({ ok: false, error: 'AUTH_REQUIRED' });
    return issuePlayToken(e.parameter.school || '', e.parameter.f || '');
  }

  return makeJson({ error: '알 수 없는 요청' });
}

// ============================================================
//  [H] 인증 액션 — 1·2·3·10번
// ============================================================
function adminLogin(data) {
  var pw = String(data.password || '');
  if (!_rlThrottle('admin', 'master'))
    return makeJson({ success: false, error: 'LOCKED', message: '시도가 많아 잠시 잠겼습니다. 10분 후 다시 시도하세요.' });

  var props = PropertiesService.getScriptProperties();
  var salt  = props.getProperty(PROP_ADMIN_SALT);
  var hash  = props.getProperty(PROP_ADMIN_HASH);
  if (!salt || !hash) return makeJson({ success: false, error: 'NOT_CONFIGURED' });

  if (_verifyPassword(pw, salt, hash)) {
    _rlReset('admin', 'master');
    return makeJson({ success: true, token: _issueToken('admin', '', TOKEN_TTL_ADMIN) });
  }
  var fails = _rlFail('admin', 'master');
  return makeJson({ success: false, error: 'WRONG', remain: Math.max(0, RL_MAX_FAILS - fails) });
}

function schoolLogin(data) {
  var school = String(data.school || '').trim();
  var pw     = String(data.password || '');
  if (!school) return makeJson({ success: false, error: '학교명이 없습니다' });

  if (!_rlThrottle('school', school))
    return makeJson({ success: false, error: 'LOCKED', message: '시도가 많아 잠시 잠겼습니다. 10분 후 다시 시도하세요.' });

  var info = _findSchool(school);
  if (!info) return makeJson({ success: false, error: 'NO_SCHOOL' });

  // 비번 검증 (해시)
  if (!_verifyPassword(pw, info.pwSalt, info.pwHash)) {
    var fails = _rlFail('school', school);
    return makeJson({ success: false, error: 'WRONG', remain: Math.max(0, RL_MAX_FAILS - fails) });
  }

  // 기간 검증
  var periodErr = _periodError(info.startDate, info.endDate);
  if (periodErr) return makeJson({ success: false, error: 'PERIOD', message: periodErr });

  _rlReset('school', school);
  return makeJson({ success: true, token: _issueToken('record', school, TOKEN_TTL_SCHOOL) });
}

// 교사 로그인 — 교사용 비밀번호 검증 후 열람용(school) 토큰 발급
//  ※ 기간 검증 없음: 녹음 기간 종료 후에도 교사 검수/열람 가능
function teacherLogin(data) {
  var school = String(data.school || '').trim();
  var pw     = String(data.password || '');
  if (!school) return makeJson({ success: false, error: '학교명이 없습니다' });

  if (!_rlThrottle('teacher', school))
    return makeJson({ success: false, error: 'LOCKED', message: '시도가 많아 잠시 잠겼습니다. 10분 후 다시 시도하세요.' });

  var info = _findSchool(school);
  if (!info) return makeJson({ success: false, error: 'NO_SCHOOL' });
  if (!info.tPwHash)
    return makeJson({ success: false, error: 'NOT_CONFIGURED',
      message: '교사용 비밀번호가 아직 설정되지 않았습니다. 관리자에게 문의하세요.' });

  if (!_verifyPassword(pw, info.tPwSalt, info.tPwHash)) {
    var fails = _rlFail('teacher', school);
    return makeJson({ success: false, error: 'WRONG', remain: Math.max(0, RL_MAX_FAILS - fails) });
  }

  _rlReset('teacher', school);
  return makeJson({ success: true, token: _issueToken('school', school, TOKEN_TTL_SCHOOL) });
}

// 공개: 짧은 코드 해석 (QR / 카톡 링크용)
function resolveCode(code) {
  code = String(code || '').trim();
  if (!code) return makeJson({ ok: false, error: 'NO_CODE' });
  var m = _lookupCode(code);
  if (!m) return makeJson({ ok: false, error: 'INVALID_CODE' });

  if (m.type === 'school') {
    // 녹음 링크용: 학교명만 반환 (기간/비번은 record가 checkPeriod로 별도 확인)
    return makeJson({ ok: true, type: 'school', school: m.school });
  }

  if (m.type === 'student') {
    // 재생 QR용: fileId 소유 검증 후 재생 토큰 발급
    var info = _findSchool(m.school);
    if (!info) return makeJson({ ok: false, error: 'NO_SCHOOL' });
    var rows = _getSchoolRecSheet(info.ssId).getDataRange().getValues();
    var owned = false;
    for (var i = 1; i < rows.length; i++) {
      if (String(rows[i][4]) === m.fileId) { owned = true; break; }
    }
    if (!owned) return makeJson({ ok: false, error: 'NO_FILE' });
    var token = _makePlayToken(m.school, m.fileId);
    return makeJson({ ok: true, type: 'student', school: m.school, fileId: m.fileId, t: token });
  }

  return makeJson({ ok: false, error: 'UNKNOWN_TYPE' });
}

// 공개: 학생 QR 코드로 음성 파일과 표시 정보를 함께 조회합니다.
function playQr(code) {
  code = String(code || '').trim();
  if (!code) return makeJson({ ok: false, error: 'NO_CODE' });

  var m = _lookupCode(code);
  if (!m || m.type !== 'student') return makeJson({ ok: false, error: 'INVALID_CODE' });
  var info = _findSchool(m.school);
  if (!info) return makeJson({ ok: false, error: 'NO_SCHOOL' });

  var rows = _getSchoolRecSheet(info.ssId).getDataRange().getValues();
  var meta = null;
  for (var i = 1; i < rows.length; i++) {
    if (String(rows[i][4]).trim() === String(m.fileId).trim()) { meta = rows[i]; break; }
  }
  if (!meta) return makeJson({ ok: false, error: 'NO_FILE' });

  try {
    var blob = DriveApp.getFileById(m.fileId).getBlob();
    return makeJson({
      ok: true, b64: Utilities.base64Encode(blob.getBytes()),
      mime: blob.getContentType(), school: m.school,
      name: meta[1], className: meta[2], downloadEnabled: info.downloadEnabled
    });
  } catch (ex) {
    return makeJson({ ok: false, error: ex.message });
  }
}

// 공개: 학교 존재 + 기간만 확인 (학생 녹음 진입 전 안내용)
function checkPeriod(school) {
  school = String(school || '').trim();
  if (!school) return makeJson({ ok: false });
  var info = _findSchool(school);
  if (!info) return makeJson({ ok: false, error: 'NO_SCHOOL' });
  var periodErr = _periodError(info.startDate, info.endDate);
  if (periodErr) return makeJson({ ok: false, error: 'PERIOD', message: periodErr });
  return makeJson({ ok: true, needPassword: !!info.pwHash });
}

// 기간 검증 헬퍼 → 문제 있으면 메시지, 정상이면 ''
function _periodError(startDate, endDate) {
  var s = startDate ? fmtDate(startDate) : '';
  var en = endDate ? fmtDate(endDate) : '';
  if (!s && !en) return '';
  var today = new Date(); today.setHours(0,0,0,0);
  if (s) { var sd = new Date(s); sd.setHours(0,0,0,0);
    if (today < sd) return '녹음 기간이 아직 시작되지 않았습니다.\n시작일 : ' + s; }
  if (en) { var ed = new Date(en); ed.setHours(23,59,59,999);
    if (today > ed) return '녹음 기간이 종료됐습니다.\n종료일 : ' + en; }
  return '';
}

// ============================================================
//  [I] 업로드 — 락 없는 낙관적 중복 방지 (전역 락 병목 제거)
//  · record 토큰 전용 (학생은 업로드만 가능, 열람 불가)
//  · 서버측 검증: MIME 화이트리스트 / 글자수 / 크기 상한
// ============================================================
function uploadRecording(data) {
  var sp = _verifyToken(data.token, 'record');
  if (!sp) return makeJson({ success: false, error: 'AUTH_REQUIRED' });

  var school    = sp.school; // 토큰의 학교로 고정 (위조 방지)
  var name      = String(data.name || '').trim();
  var className = String(data.className || '').trim();
  var audioB64  = data.audioBase64;
  var mimeType  = data.mimeType || 'audio/mp4';

  if (!name || !className || !audioB64)
    return makeJson({ success: false, error: '필수 항목 누락' });

  // ── 업로드 검증: MIME 화이트리스트 / 글자수 / 크기 상한 ──
  var ALLOWED_MIME = { 'audio/webm': 1, 'audio/mp4': 1, 'audio/ogg': 1 };
  var mimeBase = String(mimeType).split(';')[0].trim().toLowerCase(); // 'audio/webm;codecs=opus' 대응
  if (!ALLOWED_MIME[mimeBase])
    return makeJson({ success: false, error: '허용되지 않는 파일 형식입니다' });
  if (name.length > 30 || className.length > 30)
    return makeJson({ success: false, error: '이름/반 정보가 너무 깁니다' });
  if (typeof audioB64 !== 'string' || audioB64.length > 7000000) // base64 기준 ≈ 원본 5MB
    return makeJson({ success: false, error: '파일이 너무 큽니다 (최대 5MB)' });

  var info = _findSchool(school);
  if (!info) return makeJson({ success: false, error: 'NO_SCHOOL' });

  try {
    var sheet = _getSchoolRecSheet(info.ssId);

    // 1차 중복 검사 (사전 차단)
    if (_findDupRow(sheet, name, className) !== -1)
      return makeJson({ success: false, error: 'ALREADY_SUBMITTED' });

    var ext = 'webm';
    if (mimeType.indexOf('mp4') !== -1) ext = 'm4a';
    if (mimeType.indexOf('ogg') !== -1) ext = 'ogg';

    var folder   = DriveApp.getFolderById(info.folderId);
    var fileName = name + '_' + className + '.' + ext;
    var bytes    = Utilities.base64Decode(audioB64);
    var blob     = Utilities.newBlob(bytes, mimeType, fileName);
    var file     = folder.createFile(blob);
    // 비공개 유지 — 공개 공유 설정하지 않음

    sheet.appendRow([new Date(), name, className, fileName, file.getId(), mimeType]);

    // 2차 검사 — 락 없는 동시 제출 레이스 해소:
    // 같은 이름·반의 "가장 위 행"이 내 행이 아니면 내 제출을 스스로 철회
    var firstRow = _findDupRow(sheet, name, className);
    var rows = sheet.getDataRange().getValues();
    if (firstRow !== -1 && String(rows[firstRow][4]) !== file.getId()) {
      for (var i = rows.length - 1; i >= 1; i--) {
        if (String(rows[i][4]) === file.getId()) { sheet.deleteRow(i + 1); break; }
      }
      try { file.setTrashed(true); } catch (te) {}
      return makeJson({ success: false, error: 'ALREADY_SUBMITTED' });
    }

    return makeJson({ success: true, fileId: file.getId() });
  } catch (err) {
    return makeJson({ success: false, error: err.message });
  }
}

// 이름+반이 일치하는 첫 데이터 행 인덱스(0기준) 반환. 없으면 -1
function _findDupRow(sheet, name, className) {
  var rows = sheet.getDataRange().getValues();
  for (var i = 1; i < rows.length; i++) {
    if (String(rows[i][1]).trim() === name && String(rows[i][2]).trim() === className) return i;
  }
  return -1;
}

// ============================================================
//  [J] 조회 / 스트리밍 — 2·5·8번
// ============================================================
function listRecordings(school) {
  var info = _findSchool(school);
  if (!info) return makeJson({ ok: false, error: 'NO_SCHOOL' });
  var rows = _getSchoolRecSheet(info.ssId).getDataRange().getValues();
  var students = [];
  for (var j = 1; j < rows.length; j++) {
    var fid = rows[j][4];
    students.push({
      name: rows[j][1], className: rows[j][2],
      fileName: rows[j][3], fileId: fid,
      studentCode: fid ? _getOrIssueStudentCode(school, String(fid)) : '', // 재생 QR용 짧은 코드
      timestamp: rows[j][0] ? rows[j][0].toString() : ''
    });
  }
  return makeJson({ ok: true, students: students });
}

function getMeta(school, fileId) {
  var info = _findSchool(school);
  if (!info) return makeJson({ ok: false, error: 'NO_SCHOOL' });
  var rows = _getSchoolRecSheet(info.ssId).getDataRange().getValues();
  for (var n = 1; n < rows.length; n++) {
    if (String(rows[n][4]) === fileId) {
      return makeJson({
        ok: true, school: school, name: rows[n][1], className: rows[n][2],
        downloadEnabled: info.downloadEnabled
      });
    }
  }
  return makeJson({ ok: false, error: '녹음을 찾을 수 없습니다' });
}

// 오디오 — 토큰 검증된 학교의 fileId만 반환. base64로 주되,
// 파일은 Drive 비공개 유지 (5번 base64 오버헤드는 GAS 한계상 잔존, 한계 명시)
function getAudio(school, fileId) {
  var info = _findSchool(school);
  if (!info) return makeJson({ ok: false, error: 'NO_SCHOOL' });

  // fileId가 정말 이 학교 소속인지 시트로 교차 확인 (8번: 임의 fileId 접근 차단)
  var rows = _getSchoolRecSheet(info.ssId).getDataRange().getValues();
  var owned = false, meta = null;
  for (var r = 1; r < rows.length; r++) {
    if (String(rows[r][4]) === fileId) { owned = true; meta = rows[r]; break; }
  }
  if (!owned) return makeJson({ ok: false, error: '권한이 없거나 녹음을 찾을 수 없습니다' });

  try {
    var blob = DriveApp.getFileById(fileId).getBlob();
    return makeJson({
      ok: true,
      b64: Utilities.base64Encode(blob.getBytes()),
      mime: blob.getContentType(),
      school: school, name: meta[1], className: meta[2],
      downloadEnabled: info.downloadEnabled
    });
  } catch (ex) {
    return makeJson({ ok: false, error: ex.message });
  }
}

// ── play 토큰: fileId+school에 묶인 서명 (QR에 내장, 비번 없이 재생 허용) ──
//  payload: { scope:'play', school, fid, exp }
//  졸업앨범 QR은 인쇄물이라 만료를 매우 길게(졸업연도+N년) 두되,
//  retainUntil 보관정책으로 파일 자체가 정리되면 자연히 무효화됨.
var PLAY_TOKEN_TTL_DAYS = 1825; // 5년

function issuePlayToken(school, fileId) {
  school = String(school || '').trim();
  if (!school || !fileId) return makeJson({ ok: false, error: 'school/fileId 누락' });
  var info = _findSchool(school);
  if (!info) return makeJson({ ok: false, error: 'NO_SCHOOL' });
  // 해당 fileId가 이 학교 소속인지 확인
  var rows = _getSchoolRecSheet(info.ssId).getDataRange().getValues();
  var owned = false;
  for (var i = 1; i < rows.length; i++) {
    if (String(rows[i][4]) === fileId) { owned = true; break; }
  }
  if (!owned) return makeJson({ ok: false, error: '해당 학교의 녹음이 아닙니다' });

  return makeJson({ ok: true, token: _makePlayToken(school, fileId) });
}

// 재생 토큰 문자열 생성 (issuePlayToken / resolveCode 공용)
function _makePlayToken(school, fileId) {
  var payload = {
    scope: 'play', school: school, fid: fileId, kid: _activeKid(),
    exp: Date.now() + PLAY_TOKEN_TTL_DAYS * 24 * 60 * 60 * 1000
  };
  var body = _b64url(JSON.stringify(payload));
  return body + '.' + _sign(body);
}

function _verifyPlayToken(token, school, fileId) {
  try {
    if (!token || token.indexOf('.') === -1) return false;
    var parts = token.split('.');
    var p = JSON.parse(_b64urlDecode(parts[0]));
    var kid = p.kid || 'v1';                             // 구형 QR 호환
    if (_isRevokedKid(kid)) return false;
    if (!_keyForKid(kid)) return false;
    if (!_constantTimeEquals(parts[1], _signWith(kid, parts[0]))) return false;
    if (p.scope !== 'play') return false;
    if (Date.now() > p.exp) return false;
    if (String(p.school).trim() !== String(school).trim()) return false;
    if (String(p.fid) !== String(fileId)) return false;
    return true;
  } catch (e) { return false; }
}

// 공개 재생 — play 토큰 검증 후 비공개 파일을 b64로 반환
function playAudio(school, fileId, token) {
  if (!_verifyPlayToken(token, school, fileId))
    return makeJson({ ok: false, error: 'AUTH_REQUIRED' });
  var info = _findSchool(school);
  if (!info) return makeJson({ ok: false, error: 'NO_SCHOOL' });

  var rows = _getSchoolRecSheet(info.ssId).getDataRange().getValues();
  var meta = null;
  for (var r = 1; r < rows.length; r++) {
    if (String(rows[r][4]) === fileId) { meta = rows[r]; break; }
  }
  if (!meta) return makeJson({ ok: false, error: '녹음을 찾을 수 없습니다' });

  try {
    var blob = DriveApp.getFileById(fileId).getBlob();
    return makeJson({
      ok: true,
      b64: Utilities.base64Encode(blob.getBytes()),
      mime: blob.getContentType(),
      school: school, name: meta[1], className: meta[2],
      downloadEnabled: info.downloadEnabled
    });
  } catch (ex) {
    return makeJson({ ok: false, error: ex.message });
  }
}

// 녹음 삭제 (관리자) — 학교 스코프 안에서만
function deleteRecording(school, fileId) {
  if (!fileId) return makeJson({ success: false, error: 'fileId 없음' });
  var info = _findSchool(school);
  if (!info) return makeJson({ success: false, error: 'NO_SCHOOL' });
  try {
    var sheet = _getSchoolRecSheet(info.ssId);
    var rows  = sheet.getDataRange().getValues();
    var hit = false;
    for (var i = rows.length - 1; i >= 1; i--) {
      if (String(rows[i][4]).trim() === String(fileId).trim()) {
        try { DriveApp.getFileById(fileId).setTrashed(true); } catch (fe) {}
        sheet.deleteRow(i + 1);
        hit = true;
        break;
      }
    }
    return makeJson({ success: hit, error: hit ? '' : '해당 녹음을 찾을 수 없습니다' });
  } catch (err) {
    return makeJson({ success: false, error: err.message });
  }
}

// ============================================================
//  [K] 보관 정책 — 11번
//  ------------------------------------------------------------
//  retainUntil 이 지난 학교의 파일/시트를 휴지통으로.
//  · 관리자 수동 호출(purgeExpired) 또는
//  · 시간 기반 트리거로 자동 실행 가능 (installPurgeTrigger).
// ============================================================
function purgeExpired() {
  var sh = _getRegistrySheet();
  var values = sh.getDataRange().getValues();
  var today = new Date(); today.setHours(0,0,0,0);
  var purged = [];
  for (var i = 1; i < values.length; i++) {
    var school = values[i][0];
    var retain = values[i][9];
    if (!school || !retain) continue;
    var rd = (retain instanceof Date) ? retain : new Date(retain);
    if (isNaN(rd)) continue;
    rd.setHours(23,59,59,999);
    if (today > rd) {
      try { if (values[i][1]) DriveApp.getFileById(values[i][1]).setTrashed(true); } catch(e1){}
      try { if (values[i][2]) DriveApp.getFolderById(values[i][2]).setTrashed(true); } catch(e2){}
      purged.push(school);
    }
  }
  return makeJson({ success: true, purged: purged });
}

// 시간 기반 자동 보관정리 트리거 설치 (에디터에서 1회 실행)
function installPurgeTrigger() {
  var triggers = ScriptApp.getProjectTriggers();
  for (var i = 0; i < triggers.length; i++) {
    if (triggers[i].getHandlerFunction() === 'purgeExpired') return; // 이미 있음
  }
  ScriptApp.newTrigger('purgeExpired').timeBased().everyDays(1).atHour(3).create();
  Logger.log('보관정리 트리거 설치 완료 (매일 새벽 3시)');
}

// ============================================================
//  [L] 일일 자동 백업 — registry + 학교별 시트 사본, 7일 순환 보관
//  ※ 음성 파일 원본은 용량 문제로 사본을 만들지 않음 (Drive가 원본 저장소)
//     이 백업은 "시트 오염·실수 삭제" 시 메타데이터 복구용
// ============================================================
var BACKUP_ROOT_NAME = '졸업앨범_백업';
var BACKUP_KEEP_DAYS = 7;

function dailyBackup() {
  var root      = _getOrCreateFolder(DriveApp.getRootFolder(), BACKUP_ROOT_NAME);
  var stamp     = fmtDate(new Date());
  var dayFolder = _getOrCreateFolder(root, 'backup_' + stamp);

  // 관리자 페이지 백업 목록에서 확인·복원할 수 있는 JSON 스냅샷도 보관합니다.
  try { _createRegistryBackup('auto'); }
  catch (backupErr) { Logger.log('Registry JSON 백업 실패: ' + backupErr.message); }

  // 1) registry 사본
  var regId = REGISTRY_SS_ID ||
              PropertiesService.getScriptProperties().getProperty(PROP_REGISTRY_ID);
  try { DriveApp.getFileById(regId).makeCopy('registry_' + stamp, dayFolder); } catch (e0) {}

  // 2) 각 학교 스프레드시트 사본
  var values = _getRegistrySheet().getDataRange().getValues();
  for (var i = 1; i < values.length; i++) {
    var ssId = values[i][1];
    if (!ssId) continue;
    try {
      DriveApp.getFileById(ssId).makeCopy('졸업앨범_' + values[i][0] + '_' + stamp, dayFolder);
    } catch (e1) {}
  }

  // 3) 보관일 초과 백업 폴더 정리
  var cutoff = new Date(); cutoff.setDate(cutoff.getDate() - BACKUP_KEEP_DAYS);
  var iter = root.getFolders();
  while (iter.hasNext()) {
    var f = iter.next();
    var m = f.getName().match(/^backup_(\d{4}-\d{2}-\d{2})$/);
    if (!m) continue;
    var d = new Date(m[1]);
    if (!isNaN(d) && d < cutoff) { try { f.setTrashed(true); } catch (e2) {} }
  }
}

// 백업 트리거 설치 — 에디터에서 1회 실행 (매일 새벽 2시, 새벽 3시 보관정리 전에 실행)
function installBackupTrigger() {
  var triggers = ScriptApp.getProjectTriggers();
  for (var i = 0; i < triggers.length; i++) {
    if (triggers[i].getHandlerFunction() === 'dailyBackup') return; // 이미 있음
  }
  ScriptApp.newTrigger('dailyBackup').timeBased().everyDays(1).atHour(2).create();
  Logger.log('백업 트리거 설치 완료 (매일 새벽 2시, ' + BACKUP_KEEP_DAYS + '일 보관)');
}

// 관리자 페이지의 수동 백업·목록·복원 API가 사용하는 registry JSON 백업.
// 기존 dailyBackup의 스프레드시트 사본 백업은 그대로 유지합니다.
function _getRegistryBackupFolder(createIfMissing) {
  var folders = DriveApp.getFoldersByName(BACKUP_ROOT_NAME);
  if (folders.hasNext()) return folders.next();
  return createIfMissing ? DriveApp.getRootFolder().createFolder(BACKUP_ROOT_NAME) : null;
}

function _createRegistryBackup(reason) {
  var root = _getRegistryBackupFolder(true);
  var registryRows = _getRegistrySheet().getDataRange().getValues();
  var codesRows = _getCodesSheet().getDataRange().getValues();
  var now = new Date();
  var stamp = Utilities.formatDate(now, Session.getScriptTimeZone(), 'yyyy-MM-dd_HHmmss');
  var payload = {
    format: 'registry_backup_v1',
    createdAt: now.toISOString(),
    registry: registryRows,
    codes: codesRows
  };
  var file = root.createFile(
    'registry_backup_' + stamp + '_' + reason + '.json',
    JSON.stringify(payload),
    MimeType.PLAIN_TEXT
  );
  _pruneRegistryBackups(root, 60);
  return {
    fileId: file.getId(), fileName: file.getName(),
    schoolCount: Math.max(0, registryRows.length - 1),
    codeCount: Math.max(0, codesRows.length - 1)
  };
}

function _pruneRegistryBackups(root, keepCount) {
  var iter = root.getFiles();
  var files = [];
  while (iter.hasNext()) {
    var f = iter.next();
    if (/^registry_backup_.*\.json$/i.test(f.getName())) {
      files.push({ file: f, created: f.getDateCreated().getTime() });
    }
  }
  files.sort(function(a, b) { return b.created - a.created; });
  for (var i = keepCount; i < files.length; i++) {
    try { files[i].file.setTrashed(true); } catch (e) {}
  }
}

function backupNow() {
  try {
    var result = _createRegistryBackup('manual');
    return makeJson({ ok: true, fileId: result.fileId, fileName: result.fileName,
      schoolCount: result.schoolCount, codeCount: result.codeCount });
  } catch (err) {
    return makeJson({ ok: false, error: err.message });
  }
}

function listBackups() {
  try {
    var root = _getRegistryBackupFolder(false);
    if (!root) return makeJson({ ok: true, backups: [] });
    var iter = root.getFiles();
    var backups = [];
    while (iter.hasNext()) {
      var f = iter.next();
      if (!/^registry_backup_.*\.json$/i.test(f.getName())) continue;
      backups.push({
        fileId: f.getId(), fileName: f.getName(),
        createdAt: f.getDateCreated().toISOString(), size: f.getSize()
      });
    }
    backups.sort(function(a, b) { return new Date(b.createdAt) - new Date(a.createdAt); });
    return makeJson({ ok: true, backups: backups });
  } catch (err) {
    return makeJson({ ok: false, error: err.message });
  }
}

function _replaceSheetValues(sheet, rows) {
  if (!Array.isArray(rows) || !rows.length || !Array.isArray(rows[0]))
    throw new Error('백업 시트 데이터 형식이 올바르지 않습니다.');
  var width = rows.reduce(function(max, row) {
    if (!Array.isArray(row)) throw new Error('백업 행 형식이 올바르지 않습니다.');
    return Math.max(max, row.length);
  }, 0);
  if (!width) throw new Error('백업 시트에 열이 없습니다.');
  var normalized = rows.map(function(row) {
    var copy = row.slice();
    while (copy.length < width) copy.push('');
    return copy;
  });
  var maxRows = sheet.getMaxRows();
  var maxCols = sheet.getMaxColumns();
  if (maxRows < normalized.length) sheet.insertRowsAfter(maxRows, normalized.length - maxRows);
  if (maxCols < width) sheet.insertColumnsAfter(maxCols, width - maxCols);
  sheet.clearContents();
  sheet.getRange(1, 1, normalized.length, width).setValues(normalized);
  sheet.setFrozenRows(1);
}

function restoreBackup(backupFileId) {
  if (!backupFileId) return makeJson({ ok: false, error: '백업 파일 ID가 없습니다.' });
  try {
    var root = _getRegistryBackupFolder(false);
    if (!root) return makeJson({ ok: false, error: '백업 폴더를 찾을 수 없습니다.' });
    var file = DriveApp.getFileById(String(backupFileId));
    if (!/^registry_backup_.*\.json$/i.test(file.getName()))
      return makeJson({ ok: false, error: '복원할 수 있는 registry 백업 파일이 아닙니다.' });
    var parents = file.getParents();
    var inBackupFolder = false;
    while (parents.hasNext()) {
      if (parents.next().getId() === root.getId()) { inBackupFolder = true; break; }
    }
    if (!inBackupFolder) return makeJson({ ok: false, error: '지정된 백업 폴더의 파일이 아닙니다.' });

    var payload = JSON.parse(file.getBlob().getDataAsString());
    if (!payload || payload.format !== 'registry_backup_v1' ||
        !Array.isArray(payload.registry) || !Array.isArray(payload.codes) ||
        !payload.registry.length || !payload.codes.length ||
        String(payload.registry[0][0]) !== 'school' ||
        String(payload.codes[0][0]) !== 'code') {
      return makeJson({ ok: false, error: '백업 파일의 형식 또는 헤더가 올바르지 않습니다.' });
    }

    // 복원 전 현재 상태를 별도 파일로 보존해 즉시 되돌릴 수 있게 합니다.
    _createRegistryBackup('preRestore');
    _replaceSheetValues(_getRegistrySheet(), payload.registry);
    _replaceSheetValues(_getCodesSheet(), payload.codes);
    return makeJson({ ok: true,
      restoredSchools: Math.max(0, payload.registry.length - 1),
      restoredCodes: Math.max(0, payload.codes.length - 1) });
  } catch (err) {
    return makeJson({ ok: false, error: err.message });
  }
}

// 관리자 설정 탭에서 신규 학교의 기본 저장 폴더를 지정합니다.
function _extractFolderId(input) {
  var value = String(input || '').trim();
  if (!value) return '';
  var match = value.match(/\/folders\/([a-zA-Z0-9_-]+)/);
  if (match) return match[1];
  match = value.match(/[?&]id=([a-zA-Z0-9_-]+)/);
  return match ? match[1] : value;
}

function setStorageConfig(data) {
  var props = PropertiesService.getScriptProperties();
  var folderId = _extractFolderId(data.rootFolderId);
  if (!folderId) {
    props.deleteProperty(PROP_ROOT_FOLDER_ID);
    return makeJson({ ok: true, cleared: true });
  }
  try {
    var folder = DriveApp.getFolderById(folderId);
    var name = folder.getName(); // 접근 권한 확인
    props.setProperty(PROP_ROOT_FOLDER_ID, folderId);
    return makeJson({ ok: true, rootFolderId: folderId, rootFolderName: name });
  } catch (err) {
    return makeJson({ ok: false, error: '폴더를 찾을 수 없거나 접근 권한이 없습니다.' });
  }
}

function storageConfig() {
  var folderId = PropertiesService.getScriptProperties().getProperty(PROP_ROOT_FOLDER_ID);
  if (!folderId) return makeJson({ ok: true });
  try {
    var folder = DriveApp.getFolderById(folderId);
    return makeJson({ ok: true, rootFolderId: folderId, rootFolderName: folder.getName() });
  } catch (err) {
    return makeJson({ ok: false, error: '저장 폴더에 접근할 수 없습니다.' });
  }
}

function prewarm() {
  try {
    _getRegistrySheet().getLastRow();
    return makeJson({ ok: true });
  } catch (err) {
    return makeJson({ ok: false, error: err.message });
  }
}

// ============================================================
//  [전체 초기화] 모든 학교/녹음/코드 삭제 (테스트 정리용)
//  ※ 에디터에서 수동 실행. 되돌릴 수 없으니 주의.
//  - 각 학교 Drive 폴더 + 스프레드시트를 휴지통으로
//  - registry / codes 시트를 헤더만 남기고 비움
//  - HMAC키·관리자비번 등 설정값은 유지
// ============================================================
function resetAllData(confirmText) {
  // 안전핀: 확인 문자열 없이 실행하면 아무것도 삭제하지 않음
  if (confirmText !== '전체삭제확인') {
    Logger.log('⚠ 안전핀 작동 — 아무것도 삭제되지 않았습니다.');
    Logger.log('정말 전체 삭제하려면 에디터에서 resetAllData("전체삭제확인") 형태로 실행하세요.');
    return;
  }
  var sh = _getRegistrySheet();
  var values = sh.getDataRange().getValues();
  var trashed = 0;
  for (var i = 1; i < values.length; i++) {
    try { if (values[i][1]) DriveApp.getFileById(values[i][1]).setTrashed(true); } catch (e1) {}   // ssId
    try { if (values[i][2]) DriveApp.getFolderById(values[i][2]).setTrashed(true); } catch (e2) {}  // folderId
    trashed++;
  }
  // registry 비우기 (헤더 1행만 유지)
  if (sh.getLastRow() > 1) {
    sh.deleteRows(2, sh.getLastRow() - 1);
  }
  // codes 비우기
  try {
    var cs = _getCodesSheet();
    if (cs.getLastRow() > 1) cs.deleteRows(2, cs.getLastRow() - 1);
  } catch (e3) {}

  Logger.log('─────────────────────────');
  Logger.log('전체 초기화 완료');
  Logger.log('휴지통으로 보낸 학교 수: ' + trashed);
  Logger.log('registry / codes 시트를 헤더만 남기고 비웠습니다.');
  Logger.log('※ Drive 휴지통은 30일 후 자동 삭제되며, 수동으로 영구삭제 가능합니다.');
  Logger.log('─────────────────────────');
}

// ============================================================
//  [E] 공용 유틸
// ============================================================
function makeJson(data) {
  return ContentService
    .createTextOutput(JSON.stringify(data))
    .setMimeType(ContentService.MimeType.JSON);
}

function _randomToken(byteLen) {
  var bytes = [];
  for (var i = 0; i < byteLen; i++) bytes.push(Math.floor(Math.random() * 256));
  // 더 강한 엔트로피: 현재시각 + UUID 혼합
  var seed = Utilities.computeDigest(
    Utilities.DigestAlgorithm.SHA_256,
    Utilities.getUuid() + Date.now() + bytes.join(',')
  );
  return _bytesToHex(seed).substring(0, byteLen * 2);
}

function _bytesToHex(bytes) {
  var hex = '';
  for (var i = 0; i < bytes.length; i++) {
    var b = bytes[i] < 0 ? bytes[i] + 256 : bytes[i];
    hex += ('0' + b.toString(16)).slice(-2);
  }
  return hex;
}

function _b64url(str) {
  return Utilities.base64EncodeWebSafe(
    Utilities.newBlob(str).getBytes()
  ).replace(/=+$/, '');
}

function _b64urlDecode(b64) {
  var pad = b64.length % 4;
  if (pad) b64 += '===='.slice(pad);
  return Utilities.newBlob(Utilities.base64DecodeWebSafe(b64)).getDataAsString();
}

// 날짜값(Date 객체 또는 문자열)을 "YYYY-MM-DD" 형식으로 반환
function fmtDate(val) {
  if (!val) return '';
  var d = (val instanceof Date) ? val : new Date(val);
  if (isNaN(d)) return String(val).substring(0, 10);
  var y  = d.getFullYear();
  var m  = String(d.getMonth() + 1).padStart(2, '0');
  var dd = String(d.getDate()).padStart(2, '0');
  return y + '-' + m + '-' + dd;
}

// ------------------------------------------------------------
//  자가 점검 — 에디터에서 실행해 토대 함수 동작 확인
// ------------------------------------------------------------
function _selfTest() {
  // 1) 해시 왕복
  var salt = _randomToken(16);
  var h = _hashPassword('test1234', salt);
  Logger.log('해시 검증(true 기대): ' + _verifyPassword('test1234', salt, h));
  Logger.log('해시 검증(false 기대): ' + _verifyPassword('wrong', salt, h));

  // 2) 토큰 왕복 (HMAC 키 필요 → initSetup 후 실행)
  if (PropertiesService.getScriptProperties().getProperty(PROP_HMAC_KEY)) {
    var t = _issueToken('school', '테스트초', 1);
    var p = _verifyToken(t, 'school');
    Logger.log('토큰 검증(payload 기대): ' + JSON.stringify(p));
    Logger.log('토큰 scope 불일치(null 기대): ' + _verifyToken(t, 'admin'));
    Logger.log('토큰 위조(null 기대): ' + _verifyToken(t + 'x', 'school'));
  } else {
    Logger.log('HMAC 키 없음 — initSetup() 먼저 실행하세요.');
  }
}

