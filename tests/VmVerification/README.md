# App PIN Guard 2.0 VM 검증 절차

이 절차는 격리된 Windows 10/11 x64 VM에서만 수행한다. 호스트 PC나 실사용 계정에서는 실행하지 않는다. 시험 PIN 원문과 PIN 해시는 화면 캡처, JSON, Markdown, 로그에 남기지 않는다.

## 준비

- 공개 1.3.0 `Setup.exe`와 로컬 후보 `2.0.0-alpha.4` `Setup.exe`를 VM에 복사한다.
- alpha.4 기대 SHA-256은 `5290753AA0EBB137C53E7470CA8F02817CF5BC9F3EBC3A5E7F310E36FFCD17C3`이다.
- 시험용 Win32 앱, 브라우저, 실제 MSIX 앱을 정한다. 업무 데이터가 없는 앱만 사용한다.
- 관리자 PowerShell에서 이 폴더의 `Collect-Evidence.ps1`을 실행한다. `-ProtectedExecutableNames`에는 시험용 Win32 실행 파일 이름을 적는다.

```powershell
.\Collect-Evidence.ps1 -SetupExePath 'C:\VM-Test\Setup.exe' -ProtectedExecutableNames @('notepad.exe') -OutputDirectory 'C:\VM-Test\Evidence\stage-name'
```

## 1. 1.3.0 기준 상태와 체크포인트

1. 공개 1.3.0을 새 VM에 설치한다.
2. 시험 PIN, 시험용 보호 앱, 자동 시작을 설정한다. PIN은 증거에 기록하지 않는다.
3. 앱 표시 버전, 보호 목록, `WindowsAppProtectorService`, 예약 작업 `Windows App Protector` 상태를 기록한다.
4. 1.3.0 설치 파일을 지정해 증거 수집 스크립트를 실행한다.
5. VM을 완전히 종료하고 `AppPinGuard-1.3.0-baseline` 체크포인트를 만든다.

## 2. alpha.4 업그레이드와 재부팅

1. alpha.4 설치 파일의 SHA-256이 준비 단계의 값과 같은지 확인한다.
2. 1.3.0 위에 alpha.4를 설치한다. 제거 후 새 설치가 아니라 업그레이드 흐름을 사용한다.
3. 기존 PIN으로 관리 화면 인증이 되는지, 보호 목록과 예약 작업이 보존되는지 확인한다.
4. 표시 이름이 `App PIN Guard`, 버전이 `2.0.0-alpha.4`인지 확인한다.
5. 서비스 시작 유형이 자동이고 실행 중인지 확인한 뒤 VM을 재부팅한다.
6. 로그인 후 서비스와 현재 대화형 세션의 `WindowsAppProtector.WindowAgent.exe`가 각각 실행 중인지 확인한다.
7. alpha.4 설치 파일을 지정해 증거 수집 스크립트를 실행한다.

## 3. Launch Gate PIN 흐름

1. 설정에서 Launch Gate를 켜고 시험용 Win32 앱을 잠근다.
2. 앱 실행 시 Gate PIN 창이 표시되고 대상 앱이 먼저 실행되지 않는지 확인한다.
3. **취소:** 앱이 실행되지 않아야 한다.
4. **오답:** 앱이 실행되지 않아야 하며 실패 제한 상태가 서비스 재시작 후에도 유지되는지 확인한다.
5. **정답:** 앱이 원래 인자와 현재 사용자 권한으로 실행되는지 확인한다.
6. **종료 후 재잠금:** 해당 옵션을 켜고 앱을 종료한 뒤 다시 실행하면 PIN을 다시 요구해야 한다.
7. **허용 시간 만료:** 허용 시간을 짧게 설정하고 만료 전에는 허용, 만료 후에는 PIN 재요구인지 확인한다.
8. IFEO의 `Debugger`, `UseFilter`, `WAP.Launch.*` 값을 증거 수집 스크립트로 기록한다.

## 4. 브라우저·MSIX 창 감시와 복구

1. 시험 브라우저를 전체 경로 기준으로 등록하고 실제 MSIX 앱을 패키지 기준으로 등록한다.
2. 두 앱을 잠갔을 때 해당 창만 숨겨지고 같은 이름의 다른 경로 앱은 영향이 없는지 확인한다.
3. 앱별 잠금 해제 후 해당 창만 복원되는지 확인한다.
4. 관리 UI를 종료한 상태에서도 창 보호가 유지되는지 확인한다.
5. `WindowsAppProtector.WindowAgent.exe`를 시험 VM에서만 강제 종료한다.
6. 서비스가 현재 세션의 에이전트를 다시 시작하고 창 보호가 계속되는지 확인한다.

## 5. 릴리스 판단 기록

1. 각 단계마다 OS 빌드, 후보 설치 파일 SHA-256, 통과/실패, 관찰 내용을 기록한다.
2. 서비스 재시작, 재부팅, UI 종료, 에이전트 재시작 뒤 결과를 별도 항목으로 남긴다.
3. 실패 또는 미실행 항목을 통과로 기록하지 않는다.
4. Windows 10과 Windows 11 결과를 섞지 않고 각각 JSON·Markdown 보고서로 보관한다.
5. 이름 변경·복사 우회는 이번 VM 통과 기준이 아니라 `docs/DESIGN-rename-bypass.md`의 후속 구현 항목으로 남긴다.
